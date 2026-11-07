package port49d

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/blanketfish/port49/internal/broker"
	"github.com/blanketfish/port49/internal/certstatus"
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/healthcheck"
	"github.com/blanketfish/port49/internal/inventory"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/printsafe"
	"github.com/blanketfish/port49/internal/session"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/crypt"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
	"github.com/blanketfish/port49/internal/store/guard"
	"github.com/blanketfish/port49/internal/store/placement"
	"github.com/blanketfish/port49/internal/token"
	"github.com/blanketfish/port49/internal/version"
)

// brokerSubcommands is every subcommand port49-broker dispatches, by name. BrokerMain dispatches
// from this table and BrokerSubcommands lists it, so the docs lint (tests/ci) cannot disagree
// with it.
var brokerSubcommands = map[string]func(args []string) int{
	"revoke": func(a []string) int { return offlineRevoke(a, os.Stdout, os.Stderr) },
	"init-enrollments": func(a []string) int {
		return enrollmentsCmd("port49-broker", "init-enrollments", a, os.Stdout, os.Stderr)
	},
	"export-enrollments": func(a []string) int {
		return enrollmentsCmd("port49-broker", "export-enrollments", a, os.Stdout, os.Stderr)
	},
	"forget-issuer": func(a []string) int { return forgetIssuer(a, os.Stdout, os.Stderr) },
	"healthcheck": func(a []string) int {
		return healthcheck.Command("port49-broker", "/etc/port49/port49-broker.yaml", ":9050", a, os.Stderr)
	},
	"init-issuer": func(a []string) int {
		return issuerCmd("port49-broker", "init-issuer", "/etc/port49/port49-broker.yaml", config.LoadBroker, a,
			os.Stdout, os.Stderr)
	},
	"rotate-issuer": func(a []string) int {
		return issuerCmd("port49-broker", "rotate-issuer", "/etc/port49/port49-broker.yaml", config.LoadBroker, a,
			os.Stdout, os.Stderr)
	},
}

// BrokerSubcommands is the names of port49-broker's subcommands, sorted.
func BrokerSubcommands() []string { return subcommandNames(brokerSubcommands) }

// BrokerMain runs port49-broker with args (os.Args[1:]) and returns its
// exit code (plan 7e): port49d's broker path as a process of its own on
// etcd, with no TACACS+ listener, on the broker's identity alone. It takes
// --config and nothing else, or the subcommands `revoke --offline`
// (offlineRevoke; Ruling 13) and init-enrollments and export-enrollments.
func BrokerMain(args []string) int {
	if len(args) > 0 {
		if cmd, ok := brokerSubcommands[args[0]]; ok {
			return cmd(args[1:])
		}
	}
	fs := flag.NewFlagSet("port49-broker", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/port49/port49-broker.yaml", "path to port49-broker.yaml")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		// The exit codes flag.ExitOnError would have used.
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Fprintln(os.Stdout, version.Line("port49-broker"))
		return 0
	}
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: port49-broker [--config FILE], or port49-broker revoke|init-enrollments|export-enrollments|init-issuer|rotate-issuer|forget-issuer …")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := runBroker(ctx, *cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, "port49-broker:", err)
		return 1
	}
	return 0
}

// brokerStores is port49-broker's store (openBroker): raw is the broker's
// etcd store outside the guard, for the hold, the sweep and the records;
// st is its fenced, guarded and sealed layer, which the API, the minter
// and the runner's passes read and write through. ctxRev and markRev are
// the revisions the ledger and the marks were loaded at, which the feeds
// follow from.
type brokerStores struct {
	raw             *etcdstore.Store
	st              store.Store
	ctxRev, markRev uint64
	// followContexts keeps the ledger following the store's contexts until
	// its ctx ends (crypt.FollowContexts), from ctxRev.
	followContexts func(ctx context.Context)
	// dir is the directory store's raw handle, the broker's identity on it:
	// the session store's own in a shared store. fresh is how current the
	// marks this replica follows from it are (plan 11a, R17). logouts is
	// this replica's copy of the directory's logout records, loaded at
	// logoutRev (R26).
	dir       *dirHandle
	fresh     *store.Freshness
	logouts   *store.LogoutSet
	logoutRev uint64
	// issuer is the issuing CA read once at the start: the record is checked
	// against it and the broker issues from it (decision 53 ruling 10).
	issuer *loadedIssuer
}

// startRetry runs f until it succeeds, ctx ends, or it fails with an error
// that is neither an outage nor one of also: an outage is said once (and again
// if it changes), since nothing is served meanwhile, and each wait follows the
// store wait's schedule (retryWait).
func startRetry(ctx context.Context, out io.Writer, f func() error, also ...error) error {
	var say outageSayer
	for failed := 1; ; failed++ {
		err := f()
		if err == nil || ctx.Err() != nil {
			return err
		}
		wait := errors.Is(err, store.ErrUnavailable)
		for _, a := range also {
			wait = wait || errors.Is(err, a)
		}
		if !wait {
			return err
		}
		say.say(out, fmt.Sprintf("port49-broker: %v; nothing is served yet; trying again: %s", err, storeScheduleText))
		if !retryWait(ctx, failed, retryRnd) {
			return ctx.Err()
		}
	}
}

// pagedLoadFault, set by a test, is asked before each try of the load name
// and its error returned in place of the load's: how a test puts a
// compaction between pages without racing etcd's compactor. Nil in
// production.
var pagedLoadFault func(name string) error

// pagedLoad is startRetry for a load that reads pages at one revision: the
// ledger's contexts, the marks, the logouts. A compaction between pages
// reads the whole load again (11a final review N1), after the same wait as
// an outage, so it never loops hot.
func pagedLoad(ctx context.Context, out io.Writer, name string, f func() error) error {
	compacted := 0 // in a row
	return startRetry(ctx, out, func() error {
		err := pagedLoadTry(name, f)
		if err == nil {
			return nil
		}
		err = fmt.Errorf("reading the %s: %w", name, err)
		if !errors.Is(err, store.ErrCompacted) {
			compacted = 0
			return err
		}
		// Twice in a row means the load takes longer than etcd keeps
		// revisions; say once what to change. It keeps trying: nothing is
		// refused, and the retry line below says an outage once.
		if compacted++; compacted == 2 {
			fmt.Fprintf(out, "port49-broker: the %s load keeps meeting a compaction before it finishes: raise "+
				"etcd's --auto-compaction-retention\n", name)
		}
		return err
	}, store.ErrCompacted)
}

// pagedLoadTry is one try of the load name: its fault (a test's), else f.
func pagedLoadTry(name string, f func() error) error {
	if pagedLoadFault != nil {
		if err := pagedLoadFault(name); err != nil {
			return err
		}
	}
	return f()
}

// openBroker waits for etcd on the broker's identity alone, as port49d's
// start waits (waitForStore): start_timeout, then a refusal, on a cold
// start, and nothing served meanwhile. Then, each read bounded and an
// outage said and tried again on the store wait's schedule, it loads the ledger (the record's
// marks, then every live context at one revision; plan 7e, Rulings 3, 4)
// and the marks, into marks. Its guard never ends the process
// (StopAfter 0): a broker never goes dark, and its readiness is never the
// store's (design §12); a store gone answers the API 503
// store_unavailable from the guard. Its one sealing layer is
// crypt.Wrap(guard.WrapRev(crypt.Fenced(raw, ledger), …)), so a context
// read waits for its own feed as port49d's do (Task 8a), with port49-broker's
// sayer.
func openBroker(ctx context.Context, cfg config.Config, keys crypt.Keys, m *metrics.Metrics, out io.Writer,
	ledger *crypt.Ledger, marks *store.Marks) (brokerStores, error) {
	e := cfg.Stores.Session.Etcd
	say := crypt.OnUnopenable(unopenableSayer("port49-broker", keys, out, time.Now))
	ledger.Fence().OnTimeout(m.StoreFenceTimeouts.Inc)
	b, err := waitForStore(ctx, cfg, sessionRef(cfg), m, out, false, "nothing is served yet")
	if err != nil {
		return brokerStores{}, err
	}
	retry := func(f func() error, also ...error) error { return startRetry(ctx, out, f, also...) }
	var bs brokerStores
	bs.dir = &dirHandle{}
	fail := func(err error) (brokerStores, error) {
		b.Close()
		if !cfg.Stores.Shared {
			bs.dir.close()
		}
		if ctx.Err() != nil {
			return brokerStores{}, ctx.Err()
		}
		return brokerStores{}, err
	}
	bs.fresh = store.NewFreshness(time.Now)
	if !cfg.Stores.Shared {
		// A split broker's copy is the marks, the pins and the logouts: it is
		// confirmed only while all three feeds run (final review, M4).
		bs.fresh.Need("pins", "logouts")
	}
	tellFresh(bs.fresh, m)
	// issuerCheck holds this broker's issuing CA to the one the store records
	// (decision 53 ruling 10); nothing to check where it issues nothing.
	bs.issuer = loadIssuer(cfg, time.Now())
	held, issues := bs.issuer.held()
	host, _ := os.Hostname()
	issuerCheck := func(s *etcdstore.Store, timeout time.Duration) error {
		if !issues {
			return nil
		}
		c, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return checkIssuerRecord(c, s, held, "port49-broker@"+host, out)
	}
	// startChecks is what a directory store of its own passes before it is
	// used (R27, R28), and the broker writes its key window there.
	startChecks := func(dirRaw *etcdstore.Store) error {
		de := cfg.Stores.Directory.Etcd
		if err := retry(func() error { return checkTwoStores(ctx, cfg, b, dirRaw, 4*de.CallTimeout) }); err != nil {
			return err
		}
		if err := retry(func() error {
			return checkDirectoryKeys(ctx, "port49-broker", dirRaw, directoryRef(cfg), keys, out, 4*de.CallTimeout, true)
		}); err != nil {
			return err
		}
		return retry(func() error { return issuerCheck(dirRaw, 4*de.CallTimeout) })
	}
	// snap is the region's snapshot this start serves from when the
	// directory does not answer (R19); nil when it opened.
	var snap *snapshotView
	if cfg.Stores.Shared {
		if err := retry(func() error { return issuerCheck(b, 4*e.CallTimeout) }); err != nil {
			return fail(err)
		}
		bs.dir.set(b)
	} else {
		dirRaw, derr := attempt(ctx, cfg, directoryRef(cfg), m, out, true)
		switch {
		case derr == nil:
			sayUnenforced(out, cfg, directoryRef(cfg))
		case errors.Is(derr, store.ErrUnavailable):
			ceiling := snapshotCeiling(cfg)
			v, ok, serr := loadSnapshots(ctx, b, keys, true, ceiling, 4*e.CallTimeout, out, "port49-broker")
			if serr == nil && ok {
				snap = &v
				fmt.Fprintln(out, snapshotLine("port49-broker", v, ceiling, "mints, refreshes and sign-ins are refused", derr))
				break
			}
			fmt.Fprintln(out, noSnapshotLine("port49-broker", directoryRef(cfg), derr, serr, ceiling))
			if dirRaw, derr = waitForStore(ctx, cfg, directoryRef(cfg), m, out, false, "nothing is served yet"); derr != nil {
				return fail(derr)
			}
		default:
			return fail(derr)
		}
		if dirRaw != nil {
			if err := startChecks(dirRaw); err != nil {
				dirRaw.Close()
				return fail(err)
			}
			bs.dir.set(dirRaw)
		}
	}
	// The marks are the directory's: its bound in a split.
	markBound := e.BulkTimeout
	if !cfg.Stores.Shared {
		markBound = cfg.Stores.Directory.Etcd.BulkTimeout
	}
	if err := pagedLoad(ctx, out, "ledger", func() error {
		lctx, cancel := context.WithTimeout(ctx, e.BulkTimeout)
		defer cancel()
		var known, recorded int
		var err error
		bs.ctxRev, known, recorded, err = crypt.LoadLedger(lctx, b, b, keys, ledger)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "port49-broker: ledger: %d context key(s) known (%d from the ledger record); following "+
			"the store from revision %d\n", known, recorded, bs.ctxRev)
		return nil
	}); err != nil {
		return fail(err)
	}
	if err := pagedLoad(ctx, out, "marks", func() error {
		lctx, cancel := context.WithTimeout(ctx, markBound)
		defer cancel()
		var feed store.MarkFeed = bs.dir.get()
		if snap != nil {
			feed = snapFeed{*snap}
		}
		var err error
		if bs.markRev, err = store.LoadMarks(lctx, feed, marks, nil); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return fail(err)
	}
	from := "the store"
	switch {
	case snap != nil:
		bs.markRev = 0 // the follow loads the directory afresh once it opens (N5)
		from = "the region's snapshots"
	case !cfg.Stores.Shared:
		from = "the directory store"
	}
	fmt.Fprintf(out, "port49-broker: store: %d revocation(s) in force from %s\n", marks.Len(), from)
	sayFlagged(out, "port49-broker", marks.Flagged())
	gc := guardConfig(procOf(cfg), "broker", cfg.Stores.SessionPath(), e, m, out, func(error) {})
	gc.StopAfter, gc.Unhealthy = 0, nil
	bs.raw = b
	bs.st = crypt.Wrap(guard.WrapRev(crypt.Fenced(b, ledger), gc), keys, m.CryptOpenFailures,
		crypt.WithLedger(ledger), say)
	bs.logouts = store.NewLogoutSet(time.Now)
	if !cfg.Stores.Shared {
		de := cfg.Stores.Directory.Etcd
		// The logouts, loaded before anything is served, as the marks are (R26):
		// the router is handed neither the marks nor the logouts until each has
		// loaded, so a read before then cannot find a mark "absent".
		if snap != nil {
			for _, l := range snap.logouts {
				bs.logouts.Put(l) // the union keeps the later of a key's
			}
			bs.fresh.Seed(snap.confirmed)
		} else if err := pagedLoad(ctx, out, "logouts", func() error {
			lctx, cancel := context.WithTimeout(ctx, de.BulkTimeout)
			defer cancel()
			rev, es, err := bs.dir.get().Logouts(lctx)
			if err == nil {
				bs.logouts.Merge(es) // a merge, not a replace: a load never erases a live logout (8b review I1); Len counts the live (M2)
				bs.logoutRev = rev
			}
			return err
		}); err != nil {
			return fail(err)
		}
		// The router is built over the handle, so it serves before the
		// directory opens. The directory's membership half is sealed as the
		// session's is (R13; Task 8a): the pin, the map keys, refusals, the
		// forget's tombstone.
		bs.st = placement.Wrap(placement.Config{Session: bs.st, Directory: bs.dir,
			Members: &lazyMembers{h: bs.dir, wrap: func(s *etcdstore.Store) store.Store {
				return crypt.Wrap(s, keys, m.CryptOpenFailures, crypt.WithLedger(crypt.NewLedger()), say)
			}},
			Marks: marks, Logouts: bs.logouts, LogoutDir: bs.dir,
			CallTimeout: de.CallTimeout, BulkTimeout: de.BulkTimeout,
			// Before the first check the directory is tried; after it, its answer rules.
			Reachable: func() bool { ok, why := bs.fresh.Reachable(); return ok || why == "" },
			Expired:   func() error { return ceilingErr(bs.fresh, snapshotCeiling(cfg)) },
			Say:       func(format string, args ...any) { fmt.Fprintf(out, "port49-broker: "+format+"\n", args...) }})
		if snap != nil {
			placement.SeedPins(bs.st, snap.pins)
		}
	}
	bs.followContexts = func(ctx context.Context) {
		crypt.FollowContexts(ctx, b, b, keys, ledger, bs.ctxRev,
			func(up bool) { m.StoreFeedUp.WithLabelValues("contexts").Set(b2f(up)) },
			func() { m.StoreFeedRescans.WithLabelValues("contexts").Inc() },
			func(format string, args ...any) { fmt.Fprintf(out, "port49-broker: "+format+"\n", args...) })
	}
	return bs, nil
}

// announceBroker is announce for port49-broker.yaml: each notice
// config.LoadBroker left, and the lab block's warning. Under the broker's
// role a lab: block holds the seed tokens alone (plan 7e, Ruling 2).
func announceBroker(w io.Writer, cfg *config.Config) {
	if l := cfg.Lab; l != nil {
		fmt.Fprintf(w, "port49-broker: LAB MODE: port49-broker.yaml has a lab: block, which mints %d seed "+
			"token(s) to %s at every start; a lab: block must never be in production\n", len(l.SeedTokens),
			l.SeedTokenFile)
	}
	for _, n := range cfg.Notices {
		fmt.Fprintln(w, "port49-broker:", n)
	}
}

// runBroker is port49-broker from config load to exit (plan 7e): port49d's
// broker path, with no TACACS+ listener and on the broker's identity
// alone, in this order:
//  1. the config (config.LoadBroker), and the inventory behind the policy
//     file's fence;
//  2. the metrics listener, with /healthz, /readyz (the broker's) and
//     /metrics;
//  3. the inventory service's cold start, when it names one;
//  4. broker.state_dir's owner (ownStateDir), the keys and the tag key;
//  5. the store, the ledger and the marks (openBroker), the context feed
//     following at once; this replica's copy of the marks
//     (broker.state_dir/marks.json), filled from the load, and every mark
//     it holds that the store lacks kept in force (keepCopied); and its
//     record of the restore witness (broker.state_dir/witness.json),
//     following meta/witness;
//  6. the broker; the reload guard at a start (passGuardAtStart), which
//     holds the start, not ready, while the policy file is refused against
//     the bundle last judged; this replica's bundle record (keepBundle) and
//     its ask for a full context pass; its certificate status, its
//     listener with every mark in it, and only then the marks feed;
//  7. the lab's seeds, and the API serving;
//  8. the reloader, whose pass is the whole Refresh while this replica
//     runs and its token half otherwise (Ruling 6);
//  9. the runner (runner.run): the hold, the takeover, the duties.
//
// The API serves whether or not this replica runs, and through a store
// gone: readiness is never the store's (design §12). On SIGINT or SIGTERM
// it drains: the runner lets go of the hold, and every goroutine is joined
// before the store closes. SIGHUP reloads the policy, as port49d's does.
func runBroker(parent context.Context, cfgPath string) error {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	cfg, err := config.LoadBroker(cfgPath)
	if err != nil {
		return err
	}
	ledger := crypt.NewLedger()
	// A mark outlives any grace window a context is kept past its ceiling
	// (crypt.DefaultLedgerKeep), as port49d's does.
	ledger.SetKeep(max(cfg.Session.GraceWindow+time.Hour, crypt.DefaultLedgerKeep))
	var inventoryAtStart string
	inventoryFrom := "inventory_file " + cfg.InventoryFile
	if cfg.InventoryService == nil {
		inv, v, err := fencedInventory(cfg)
		if err != nil {
			return err
		}
		cfg.Inventory, inventoryAtStart = inv, v
	}
	announceBroker(stderr, &cfg)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	reg := prometheus.NewRegistry()
	m := metrics.New(reg)
	mln, err := net.Listen("tcp", cfg.MetricsListen)
	if err != nil {
		return fmt.Errorf("metrics listener on %s: %w", cfg.MetricsListen, err)
	}
	defer mln.Close()
	// /readyz is the broker's own (broker.ReadyStarting until it serves),
	// on the metrics listener as on the API, with no certificate.
	var api atomic.Pointer[http.Handler]
	status := &statusHandler{} // GET /store/status, given the stores once they are open
	metricsErr := make(chan error, 1)
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		mux.Handle("GET /store/status", status)
		mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
			if h := api.Load(); h != nil {
				(*h).ServeHTTP(w, r)
				return
			}
			http.Error(w, broker.ReadyStarting, http.StatusServiceUnavailable)
		})
		metricsErr <- http.Serve(mln, mux)
	}()
	fmt.Fprintf(stderr, "port49-broker: metrics on %s\n", mln.Addr())

	var startDoc *inventory.Published
	var startFrom string
	var verifyKeysAtStart []ed25519.PublicKey
	var client *inventory.Client
	if svc := cfg.InventoryService; svc != nil {
		// Spec §10, cold start, as port49d's: a copy, or the service; the
		// API is not served until one.
		if verifyKeysAtStart, err = config.VerifyKeys(svc.VerifyKeyFiles); err != nil {
			return err
		}
		if client, err = inventory.NewClient(svc.URL, svc.CAFile, svc.TLSCertFile, svc.TLSKeyFile); err != nil {
			return fmt.Errorf("inventory.service: %w", err)
		}
		m.WatchInventoryAge(func() float64 { return math.NaN() })
		picks, err := coldCopies(ctx, procOf(cfg), svc, verifyKeysAtStart, client, m, nil)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		pick, err := startCopy(cfg, picks, m)
		if err != nil {
			return err
		}
		sayStart(procOf(cfg), svc, pick)
		startDoc, startFrom = pick.p, pick.from
		cfg.Inventory = startDoc.Inv
		inventoryFrom = fmt.Sprintf("the inventory service's bundle %d", startDoc.Doc.Sequence)
		m.InventoryBundleSequence.Set(float64(startDoc.Doc.Sequence))
	}

	// What the broker keeps in broker.state_dir is its own: refused if
	// anyone else owns it, before anything there is read or written.
	if err := ownStateDir(cfg.Broker.StateDir); err != nil {
		return fmt.Errorf("broker.state_dir: %w", err)
	}
	log := decision.NewJSONLinesWithFailureHook(stdout, m.DecisionLogWriteFailures.Inc)
	keys, err := cfg.EncryptionKeys()
	if err != nil {
		return err
	}
	// The tag key binds a token to the device it was minted for, derived
	// from the current encryption key as port49d derives the window it
	// accepts (runOnce).
	cur := keys.Current.Bytes()
	tagKey := token.TagKey(cur[:])
	// port49_revocations_in_force is the marks this replica enforces, set
	// before they load, or the gauge reads 0 (final review 7e-1).
	marks := store.NewMarks()
	marks.Count(func(principal, cert int) {
		m.RevocationsInForce.WithLabelValues(store.RevocationPrincipal).Set(float64(principal))
		m.RevocationsInForce.WithLabelValues(store.RevocationCert).Set(float64(cert))
	})
	// This replica's copy of the marks (Ruling 12), opened before they load.
	marksCopy := openMarksCopy(filepath.Join(cfg.Broker.StateDir, stateMarksFile), stderr)
	bs, err := openBroker(ctx, cfg, keys, m, stderr, ledger, marks)
	if err != nil {
		if ctx.Err() != nil {
			return nil // stopped while waiting for the store: nothing was served
		}
		return err
	}
	// The load is the store's marks at one revision: the copy adds each, and
	// every mark the copy holds that the store lacks stays in force here, so
	// a restart lifts no mark an etcd restore lost, before the listener is
	// built from the marks (pre-flight I5).
	stored := marks.All()
	keptAtStart := keepCopied(marksCopy, marks, stored)
	marksCopy.stand(stored)
	keptSayerAs(stderr, "port49-broker", "this replica", "at this start", "")(keptAtStart)
	// Every goroutine below is joined (wg) before the store closes.
	var wg sync.WaitGroup
	defer bs.raw.Close()
	if !cfg.Stores.Shared {
		defer bs.dir.close()
	}
	defer wg.Wait()
	defer cancel()
	// The ledger follows the store from the start's scan at once, before
	// anything reads a context (plan 7e, Ruling 3).
	wg.Add(1)
	go func() { defer wg.Done(); bs.followContexts(ctx) }()
	// This replica's record of the restore witness (Ruling 18): every
	// witness it follows, the runner's own too, kept in broker.state_dir
	// and saved once more as it stops, so it outlives an etcd restore.
	wit := openWitness(filepath.Join(cfg.Broker.StateDir, stateWitnessFile), cfg.Stores.Session.Etcd.Prefix, stderr)
	wg.Add(2)
	go func() { defer wg.Done(); wit.keep(ctx) }()
	go func() { defer wg.Done(); bs.raw.FollowWitnessLive(ctx, wit.followed) }()

	minter := token.NewMinter(bs.st, log, rand.Reader, tagKey, time.Now, cfg.Token.CandidateCap)
	brokerSrv, brk, anchors, err := buildBrokerAnchorWith(cfg, inventoryFrom, bs.st, minter, log, m, bs.issuer)
	if err != nil {
		return err
	}
	signInDone := wirePasswordSignIn(ctx, cfg, brk, keys, m, bs.dir, stderr)
	wg.Add(1)
	go func() { defer wg.Done(); <-signInDone }()
	if startDoc != nil {
		persistStart(procOf(cfg), cfg.InventoryService, coldPick{p: startDoc, from: startFrom}, m)
	}
	// Every replica runs its pool's health checks and selects for its own
	// queries; the pool closes its connections when Run returns, which is
	// before the store does (wg).
	wg.Add(1)
	go func() { defer wg.Done(); runPool(ctx, brk.Directory) }()
	wg.Add(1)
	go func() { defer wg.Done(); runKeySets(ctx, brk.Identity) }()
	brk.Sessions = session.New(bs.st, time.Now, cfg.ContextIdleTTL, cfg.Session.IndexTTL)
	brk.Marks = marks
	brk.RevokeTimeout = revokeRunTimeout
	brk.Proc = "port49-broker"
	brk.OnLift = marksCopy.Lifted // a lift over the API leaves the copy
	// MarkChanged's lines, a held connection closed and a lift a reload
	// found, go to port49-broker's stderr (Ruling T9-c).
	brk.Say = func(format string, args ...any) { fmt.Fprintf(stderr, "port49-broker: "+format+"\n", args...) }
	brokerSay := func(format string, args ...any) { fmt.Fprintf(stderr, "port49-broker: "+format+"\n", args...) }

	// The reload guard at a start (Ruling 17; pre-flight I6): a file the
	// guard refuses against the bundle last judged holds the start, with
	// nothing that mints served, until a version passes.
	if err := passGuardAtStart(ctx, cfg, bs.raw, brk.Policy, inventoryFrom, m); err != nil {
		return nil // stopped while the file was refused: nothing was served
	}
	host, _ := os.Hostname()
	who := fmt.Sprintf("port49-broker on %s (pid %d, since %s)", host, os.Getpid(),
		time.Now().UTC().Format(time.RFC3339))
	// This replica's record of the bundle it serves (Ruling 8 corrected;
	// pre-flight I3), renewed at every swap (swapped) and deleted at a
	// graceful stop. The first lands before anything that mints is served
	// (Task 15a review M-1), and so does the mark on meta/judged when it
	// names another bundle (re-review 1, I-2): until then this replica is
	// not ready. Each mint asks the gate after (skewGate), which also holds
	// every mint until a takeover is seen done for the bundle this replica
	// serves (decision 36, the mint gate at a start): its own runner's
	// (rn.tookOver), or one meta/judged names, not in doubt (openAtJudged).
	gate := newStartGate(m.BrokerMintGateClosed)
	startBundle := brk.Policy.Load().Bundle
	if err := recordStart(ctx, bs.raw, who, startBundle, cfg.Stores.Session.Etcd.HoldTTL, 4*cfg.Stores.Session.Etcd.CallTimeout,
		5*time.Second, stderr); err != nil {
		if ctx.Err() != nil {
			return nil // stopped while the records could not land: nothing was served
		}
		return err
	}
	gate.flag(startBundle)
	brk.MintGate = gate.allow
	// Read once here, after the start's mark and before the API serves: a
	// rolling restart, meta/judged already naming this bundle, mints at once.
	// Not when this replica owes a purge (no witness record, or a store below
	// it): meta/judged then may be a restored one's, and a token minted before
	// the takeover's purge would be deleted by it. A replica that finds
	// another running the keyspace (standby) does not wait: that one's
	// takeover purges, and this replica's own runs only if that one stops.
	var standby atomic.Bool // another replica runs the keyspace: its takeover purges, not this one's
	owes := func(ctx context.Context) bool {
		if standby.Load() {
			return false
		}
		rctx, cancel := context.WithTimeout(ctx, 4*cfg.Stores.Session.Etcd.CallTimeout)
		defer cancel()
		_, gone, _, err := readWitness(rctx, wit, bs.raw.Witness)
		return gone || err != nil
	}
	if _, named := judgedNames(ctx, bs.raw, startBundle, 4*cfg.Stores.Session.Etcd.CallTimeout); named && !owes(ctx) {
		gate.open(fmt.Sprintf("meta/judged names bundle %s, the one this replica serves", startBundle), stderr)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		openAtJudged(ctx, bs.raw, gate, brk.Policy, 4*cfg.Stores.Session.Etcd.CallTimeout, startGateEvery, stderr, owes)
	}()
	swapped := make(chan struct{}, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		keepBundle(ctx, bs.raw, who, brk.Policy, cfg.Stores.Session.Etcd.HoldTTL, swapped, m, stderr)
	}()
	rn := &runner{cfg: cfg, brk: brk, raw: bs.raw, st: bs.st, meta: bs.raw, ledger: ledger, keys: keys, m: m,
		judge: make(chan *policy.Policy, 1), alarm: newKeyAlarm(), who: who, copy: marksCopy, marks: marks,
		marksReloaded: make(chan struct{}, 1), witness: wit,
		holdMints: gate.purge, standby: func() { standby.Store(true) },
		tookOver: func(carried *policy.Policy) {
			gate.open(fmt.Sprintf("this replica's takeover is done (bundle %s)", carried.Bundle), stderr)
		}}
	if !cfg.Stores.Shared {
		rn.dir = bs.dir
		rn.followed = make(chan store.Revocation, 1024)
		rn.openLogoutQueue()
		rn.logouts = bs.logouts
	}
	// A replica's start and each of its swaps while it does not run ask the
	// runner for a full context pass (runner.owed): a context made from its
	// token under another bundle is then judged. Every swap, the runner's
	// own too, first marks meta/judged in doubt when it names another
	// bundle, and only then opens the gate to mints under the swapped
	// bundle (re-review 1, I-2; re-review 2, I-3): a runner that swaps and
	// stops before its settle pass leaves tokens no pass judged. The writes
	// are this goroutine's, the latest ask only, so the reloader never
	// waits on the store (Task 15 review M-5). The start's ask is tried
	// once at once, before the runner starts, so a takeover's carry covers
	// it.
	asks := make(chan string, 1)
	ask := func(bundle string) {
		select {
		case <-asks:
		default:
		}
		select {
		case asks <- bundle:
		default:
		}
	}
	putAsk := func(ctx context.Context, bundle string) error {
		actx, cancel := context.WithTimeout(ctx, 4*cfg.Stores.Session.Etcd.CallTimeout)
		defer cancel()
		if err := bs.raw.PutRefreshOwed(actx, who, bundle); err != nil {
			return fmt.Errorf("asking the runner for a full context pass (bundle %s): %w", bundle, err)
		}
		return nil
	}
	if putAsk(ctx, brk.Policy.Load().Bundle) != nil {
		ask(brk.Policy.Load().Bundle)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case b := <-asks:
				flagSwap(ctx, bs.raw, gate, who, b, cfg.Stores.Session.Etcd.HoldTTL, 4*cfg.Stores.Session.Etcd.CallTimeout,
					5*time.Second, stderr)
				if rn.running() {
					continue // the runner's own passes judge its contexts
				}
				if err := retryCtx(ctx, func() error { return putAsk(ctx, b) }); err != nil && ctx.Err() == nil {
					brokerSay("policy: %v; the runner judges this replica's contexts a token life after it last "+
						"sees it serve another bundle", err)
				}
			}
		}
	}()

	// Certificate status (spec §5.1.4; decision 33), its kept lists in
	// broker.state_dir (Ruling 12): put in force now, fetched once the API
	// serves.
	var checker *certstatus.Checker
	cs := cfg.Broker.CertificateStatus
	if cs == nil {
		brokerSay("broker: no x509 verifier is configured, so no client certificate's status is checked")
	} else if cs.Disabled {
		brokerSay("broker: certificate status checking is disabled (broker.certificate_status.disabled): a " +
			"certificate revoked at its CA keeps minting until `port49 revoke --cert`")
	} else {
		ccfg, err := certStatusConfig(*cs, certsOf(anchors), cfg.Broker.StateDir,
			"broker.client_ca_file, or a broker.identity x509 trust_anchor_file", "the broker")
		if err != nil {
			return fmt.Errorf("broker.certificate_status.%w", err)
		}
		checker = certstatus.New(ccfg, time.Now, m,
			func(format string, args ...any) { fmt.Fprintf(stderr, procOf(cfg)+": "+format+"\n", args...) })
		checker.OnNewEntry(brk.OnCRLEntry)
		for _, err := range checker.LoadPersisted() {
			brokerSay("broker: certificate status: %s", printsafe.Line(err.Error(), 300))
		}
		for _, a := range anchors {
			if line := anchorCoverLine(a, ccfg, cs.OnUnavailable); line != "" {
				brokerSay("%s", line)
				continue
			}
			for _, subject := range uncoveredIssuers(ccfg, a.cert) { // re-check R3
				brokerSay("%s", intermediateCoverLine(subject, cs.OnUnavailable))
			}
		}
		brk.CertStatus, brk.OnUnavailable = checker, cs.OnUnavailable
	}

	bln, err := net.Listen("tcp", brokerSrv.Addr)
	if err != nil {
		return fmt.Errorf("broker listener on %s: %w", brokerSrv.Addr, err)
	}
	// Capped as port49d's broker listener is (pre-flight F1; decision 32).
	// It accepts nothing until Serve's first Accept, so every mark the load
	// read is in it before any connection binds.
	bl := broker.NewListener(broker.Limit(bln, broker.MaxConns), brokerSrv.TLSConfig,
		brokerLimits(cfg, brk),
		m, time.Now, func(format string, args ...any) {
			fmt.Fprintf(stderr, procOf(cfg)+": "+format+"\n", args...)
		})
	for _, r := range marks.All() {
		bl.Revoked(r, true)
	}
	brk.Wire(bl)
	brk.Conns = bl
	// Only now the marks feed: a change told before brk.Conns was set would
	// reach no listener, and the listener holds every mark at the load's
	// revision, which the feed follows from. Keep that order. The feed tells
	// the copy every change the watch delivers and every mark a reload
	// reads (copyingFeed), this replica's own revocations included; its
	// own lifts leave the copy (Lifted).
	// Before a reload the runner's hook puts back what the store lost,
	// refusing the reload when that fails, and every other replica's keeps
	// what its copy holds and the store lacks, refusing the reload when the
	// marks cannot be read (final review 7e-1 C-1; re-review 1 C-2;
	// pre-flight 7e-2 P-3).
	// In a split the directory may not have answered at the start (R19): one
	// goroutine opens it, and each follow below waits for it.
	ready, dirErr := make(chan struct{}), make(chan error, 1)
	if cfg.Stores.Shared {
		close(ready)
	} else {
		// The record the CA is held to is in the directory: until it answers
		// and the check passes, no certificate is issued. Said once here.
		if _, issues := bs.issuer.held(); issues && bs.dir.get() == nil {
			brk.HoldIssuance()
			fmt.Fprintln(stderr, "port49-broker: issuance waits for the directory store, where the issuing CA's record "+
				"is checked; until it answers, certificates are refused (503 issuance_unavailable)")
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if bs.dir.get() == nil {
				de := cfg.Stores.Directory.Etcd
				if err := openDirectoryLater(ctx, cfg, m, stderr, bs.dir, "port49-broker", func(s *etcdstore.Store) error {
					if err := checkTwoStores(ctx, cfg, bs.raw, s, 4*de.CallTimeout); err != nil {
						return err
					}
					if err := checkDirectoryKeys(ctx, "port49-broker", s, directoryRef(cfg), keys, stderr, 4*de.CallTimeout, true); err != nil {
						return err
					}
					if held, issues := bs.issuer.held(); issues {
						host, _ := os.Hostname()
						c, cancel := context.WithTimeout(ctx, 4*de.CallTimeout)
						defer cancel()
						if err := checkIssuerRecord(c, s, held, "port49-broker@"+host, stderr); err != nil {
							return err
						}
						brk.ReleaseIssuance()
					}
					return nil
				}); err != nil {
					if ctx.Err() == nil {
						dirErr <- err // ends the run: the process exits 1 saying it
					}
					return
				}
			}
			close(ready)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			return
		case <-ready:
		}
		onMark := brk.MarkChanged
		if !cfg.Stores.Shared {
			onMark = func(c store.MarkChange) { brk.MarkChanged(c); rn.follow(c) }
		}
		store.FollowMarks(ctx, copyingFeed{MarkFeed: bs.dir.get(), copy: marksCopy}, marks, bs.markRev, onMark,
			func(up bool) { m.StoreFeedUp.WithLabelValues("marks").Set(b2f(up)); bs.fresh.FeedUp(up) },
			rn.reloadHook(ctx, m.StoreFeedRescans.WithLabelValues("marks")),
			func(format string, args ...any) { fmt.Fprintf(stderr, "port49-broker: "+format+"\n", args...) })
	}()
	// In a split, follow the pins into the router's cache (Task 8a); FollowPins
	// returns at once on a shared store.
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
			return
		case <-ready:
		}
		placement.FollowPins(ctx, bs.st, bs.dir.get(),
			func(up bool) { m.StoreFeedUp.WithLabelValues("pins").Set(b2f(up)); bs.fresh.Up("pins", up) },
			func(format string, args ...any) { fmt.Fprintf(stderr, "port49-broker: "+format+"\n", args...) })
	}()
	// In a split, follow the logouts into this replica's copy. Each one the
	// watch delivers goes to the runner, which reaches it here (Task 8c).
	if !cfg.Stores.Shared {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case <-ready:
			}
			store.FollowLogouts(ctx, bs.dir.get(), bs.logouts, bs.logoutRev, rn.followLogout,
				func(up bool) { m.StoreFeedUp.WithLabelValues("logouts").Set(b2f(up)); bs.fresh.Up("logouts", up) },
				func(format string, args ...any) { fmt.Fprintf(stderr, "port49-broker: "+format+"\n", args...) })
		}()
	}
	// In a split, this replica's snapshot records, written while its copy is
	// confirmed live (R19).
	if !cfg.Stores.Shared {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keepSnapshot(ctx, bs.raw, bs.dir, bs.fresh, keys, writerName("port49-broker"), snapshotCeiling(cfg),
				4*cfg.Stores.Directory.Etcd.CallTimeout, marks.All, func(b *brokerSnapshot) { b.Logouts, b.Pins = bs.logouts.All(), placement.CachedPins(bs.st) },
				stderr, "port49-broker")
		}()
	}
	// A copy served from a snapshot past the ceiling refuses every read of it
	// (placement.Config.Expired): said once, so the 503s have a reason.
	if !cfg.Stores.Shared {
		wg.Add(1)
		go func() { defer wg.Done(); sayBrokerCeiling(ctx, bs.fresh, snapshotCeiling(cfg), stderr) }()
	}
	// The copy's freshness: the directory read every second (R17).
	dirTimeout := cfg.Stores.Directory.Etcd.CallTimeout
	wg.Add(1)
	go func() {
		defer wg.Done()
		keepFresh(ctx, bs.dir, bs.fresh, dirTimeout, stderr, "port49-broker", cfg.Stores.Shared)
	}()

	st := newStoreStatus(cfg, bs.dir, bs.raw, bs.fresh)
	st.pending = func() int { return int(rn.pending.Load()) }
	status.set(st)

	if cfg.Lab != nil && len(cfg.Lab.SeedTokens) > 0 {
		logins, enables, err := mintSeeds(ctx, cfg, minter)
		if err != nil {
			bln.Close()
			return err
		}
		fmt.Fprintf(stderr, "port49-broker lab: %d login token(s) and %d enable token(s) minted, credentials "+
			"written to %s\n", logins, enables, cfg.Lab.SeedTokenFile)
	}

	brokerErr := make(chan error, 1)
	go func() { brokerErr <- brokerSrv.Serve(bl) }()
	h := brk.Handler()
	api.Store(&h)
	brk.SetReady(broker.ReadyServing)
	fmt.Fprintf(stderr, "port49-broker: listening on %s, metrics on %s\n", bln.Addr(), mln.Addr())

	if checker != nil {
		unavailable := map[string]string{"refuse": "refused (503, retried)", "allow": "allowed, alarmed"}
		brokerSay("broker: certificate status from %s; a status that cannot be established is %s",
			checker.Describe(), unavailable[cs.OnUnavailable])
		wg.Add(3)
		go func() { defer wg.Done(); brk.RunRevocationQueue(ctx) }()
		go func() { defer wg.Done(); checker.Run(ctx) }()
		go func() {
			defer wg.Done()
			t := time.NewTicker(cs.RefreshInterval)
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

	// Every replica runs its own reload's token half; the runner the whole
	// refresh, whose context half is its alone (Ruling 6), and the full
	// passes a replica owes.
	rel := newReloader(cfg, brk.Policy, log, rn.pass, m, time.Now)
	rel.inventory, rel.cfgPath = inventoryAtStart, cfgPath
	rel.startDocument(startDoc, startFrom)
	rel.onSettled = rn.settled
	rel.mfaUnavailable, rel.adminTouch = brk.MFAUnavailable, brk.AdminTouchLine
	if id := cfg.Broker.Identity; id != nil {
		rel.addHUP(func() { reloadAttestationRoots(id.PerLoginMFA, brk, brk.Policy.Load, brokerSay) })
	}
	rel.fullPass, rel.whole = make(chan fullPassOwed), rn.whole
	rel.onSwap = func(pol *policy.Policy) {
		select {
		case swapped <- struct{}{}:
		default:
		}
		ask(pol.Bundle)
	}
	rn.rel = rel
	wg.Add(2)
	go func() {
		defer wg.Done()
		var fetchDone <-chan struct{}
		if cfg.InventoryService != nil {
			keys := verifyKeysAtStart
			rel.verifyKeys.Store(&keys)
			fetchDone = startFetcher(ctx, rel, client, m)
		}
		rel.run(ctx, hup)
		if fetchDone != nil {
			<-fetchDone
		}
	}()
	go func() { defer wg.Done(); rn.run(ctx) }()

	var runErr error
	select {
	case err := <-metricsErr:
		runErr = fmt.Errorf("metrics listener on %s: %w", cfg.MetricsListen, err)
	case err := <-brokerErr:
		runErr = fmt.Errorf("broker listener on %s: %w", cfg.Broker.Listen, err)
	case err := <-dirErr:
		runErr = err
	case <-ctx.Done():
		fmt.Fprintln(stderr, "port49-broker: signal received, draining")
	}
	brk.SetReady(broker.ReadyDrainingOf(procOf(cfg)))
	cancel()
	// Close what Shutdown left at its timeout: the agents' held
	// connections.
	shutdownCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
	if err := brokerSrv.Shutdown(shutdownCtx); err != nil {
		brokerSrv.Close()
	}
	done()
	wg.Wait()
	fmt.Fprintln(stderr, "port49-broker: drained, exiting")
	return runErr
}
