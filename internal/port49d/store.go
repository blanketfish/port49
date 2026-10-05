package port49d

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/keyfile"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
	"github.com/rhwendt/port49/internal/store/guard"
	"github.com/rhwendt/port49/internal/store/memory"
)

// holderShape is the holder a port49-broker writes under meta/hold
// (runner), or a 7d port49d wrote.
var holderShape = regexp.MustCompile(`^port49(d|-broker) on [A-Za-z0-9._-]{0,253} \(pid [0-9]{1,10}, since [0-9TZ:+.-]{1,40}\)$`)

// lineHolder is meta/holder as a line may echo it: quoted and cut to 200
// bytes in the shape port49-broker writes, "?" otherwise. Whoever can
// write meta/ writes it, and a line must not carry its newlines or a
// megabyte of it (final review 7d-2 m-1).
func lineHolder(holder string) string {
	if !holderShape.MatchString(holder) {
		return "?"
	}
	if len(holder) > 200 {
		holder = holder[:200]
	}
	return fmt.Sprintf("%q", holder)
}

// stores is what port49d's components read and write through (plan 7d):
// on etcd the daemon's alone, its identity, guard and sealing layer, the
// broker being port49-broker (plan 7e); on memory one store for the daemon
// and the in-process broker.
type stores struct {
	// broker is the in-process broker's, the daemon's own on memory; nil
	// on etcd.
	daemon, broker store.Store
	// etcd is the daemon's raw backend on etcd. Nil on memory.
	etcd *etcdstore.Store
	// judged is etcd as meta/judged_bundle's reader, for keepDaemonBundle
	// (re-check R5): the daemon's role reads that key, not meta/judged. Nil
	// on memory.
	judged     judgedBundleReader
	persistent bool
	// follow keeps the ledger following the store's contexts, and the
	// marks, until its ctx ends (crypt.FollowContexts, store.FollowMarks).
	// runOnce runs it as soon as the stores are open, and joins it before
	// close. Nil on memory, where every write is this process's own.
	follow func(ctx context.Context)
	// probe pings the store through the daemon's guard until its ctx ends,
	// so an idle port49d still goes dark on a store gone (probe; plan 7e,
	// Ruling 11). runOnce runs and joins it as it does follow. Nil on
	// memory.
	probe func(ctx context.Context)
	close func()
}

// storeGone ends one run of port49d on etcd (Ruling 11; pre-flight I10,
// I19): a pool's store has failed or refused every call for hold_ttl. run
// then starts the next, which waits for the store with every listener
// closed, as at a start.
type storeGone struct{ why string }

func (g *storeGone) Error() string { return "store: " + g.why }

// storeFault is a store configuration port49d cannot start on: an expired
// or wrong certificate, a CA that does not verify, a key file keyfile
// refuses, roles not in force. Waiting does not mend it, unlike
// store.ErrUnavailable. A cold start exits on it; a start after a store
// gone says it and tries again, re-reading the files, so a renewed
// certificate or applied roles are picked up (Ruling 12; pre-flight I9,
// M33).
type storeFault struct{ err error }

func (f *storeFault) Error() string { return f.err.Error() }
func (f *storeFault) Unwrap() error { return f.err }

// openStores builds the stores cfg names, each sealing layer on ledger,
// the process's one (decision 35; Ruling T12-b). On etcd it waits for the
// store with every listener still closed (none is bound yet): up to
// start_timeout on a cold start (0 is for as long as it takes), and with
// no deadline when again says this run follows a store gone; then it is
// openDaemon's, on the daemon's identity alone: the broker, the hold and
// the ledger record are port49-broker's (plan 7e). gone is how the guard
// ends the run. It says each step on out. authMarks, the process's, is
// loaded from the store.
func openStores(ctx context.Context, cfg config.Config, keys crypt.Keys, m *metrics.Metrics, out io.Writer,
	rd *readiness, again bool, gone func(error), ledger *crypt.Ledger, alarm *keyAlarm,
	authMarks *store.Marks) (stores, error) {
	// One sayer for every layer, so a key is said once, not once per layer
	// (pre-flight M44).
	say := crypt.OnUnopenable(unopenableSayer("port49d", keys, out, time.Now))
	if cfg.Store.Backend != config.BackendEtcd {
		// The memory store is new and empty: every record in it is sealed
		// above its base (crypt.Ledger).
		mem := memory.New(time.Now)
		ledger.SetBase(mem.Seen() + 1)
		st := crypt.Wrap(mem, keys, m.CryptOpenFailures, crypt.WithLedger(ledger), say)
		return stores{daemon: st, broker: st, close: func() {}}, nil
	}
	ledger.Fence().OnTimeout(m.StoreFenceTimeouts.Inc)
	// A run after a store gone shows the alarm a run before raised from
	// its first scrape: the wait below is the outage, and a gauge at 0
	// through it would resolve the alert (keyAlarm; re-review I-3).
	if alarm.raised {
		m.CryptStoreKeyUnknown.Set(1)
	}
	rd.set(readyStore)
	d, err := waitForStore(ctx, cfg, m, out, again, "the listeners stay closed")
	if err != nil {
		return stores{}, err
	}
	return openDaemon(ctx, cfg, keys, m, out, again, gone, ledger, alarm, authMarks, d, say)
}

// waitForStore is a start's wait for etcd (pre-flight I9, I13, M33), on
// the identity cfg's role names (attempt): the feeds' series made first,
// then an attempt every 5s, each outage said with what stays shut
// meanwhile (closed), up to start_timeout on a cold start and with no
// deadline when again. A configuration fault ends a cold start, named;
// after a store gone it is said and tried again, re-reading the files.
func waitForStore(ctx context.Context, cfg config.Config, m *metrics.Metrics, out io.Writer, again bool,
	closed string) (*etcdstore.Store, error) {
	e := cfg.Store.Etcd
	proc := procOf(cfg)
	// Both feeds read down from here until each first runs, so an alert on
	// port49_store_feed_up == 0 fires through a wait for the store or a
	// marks load still retrying, not on an absent series; and each rescan
	// counter is there at 0, so the first rescan is an increase (final
	// review 7e-1 M-3).
	for _, feed := range []string{"contexts", "marks"} {
		m.StoreFeedUp.WithLabelValues(feed).Set(0)
		m.StoreFeedRescans.WithLabelValues(feed)
	}
	eps := strings.Join(e.Endpoints, ", ")
	var deadline time.Time
	if !again && e.StartTimeout > 0 {
		deadline = time.Now().Add(e.StartTimeout)
	}
	for {
		s, err := attempt(ctx, cfg, m, out)
		if err == nil {
			if e.Roles == config.RolesUnenforced {
				fmt.Fprintf(out, "%s: store.etcd.roles: unenforced: the daemon and the broker are not separated "+
					"on etcd; a stolen daemon key can lift revocations\n", proc)
			}
			return s, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var fault *storeFault
		switch {
		case errors.As(err, &fault) && !again:
			return nil, err // the operator's to fix; named, exit 1
		case errors.As(err, &fault):
			fmt.Fprintf(out, "%s: %v; %s; trying again in 5s\n", proc, err, closed)
		case !deadline.IsZero() && time.Now().After(deadline):
			return nil, fmt.Errorf("store: etcd at %s did not answer within store.etcd.start_timeout (%v); not "+
				"starting", eps, e.StartTimeout)
		default:
			wait := "until it answers"
			if !deadline.IsZero() {
				wait = fmt.Sprintf("up to %v", e.StartTimeout)
			}
			fmt.Fprintf(out, "%s: store: etcd at %s not answering (%v); %s; waiting %s\n", proc, eps, err, closed,
				wait)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

// procOf names the process cfg was loaded for, as its lines begin.
func procOf(cfg config.Config) string {
	if cfg.Role == config.RoleBroker {
		return "port49-broker"
	}
	return "port49d"
}

// openDaemon is openStores's etcd branch for port49d with no broker in
// the process (plan 7e, Ruling 11), once d, the daemon's identity, answers.
// There is no hold: any number of port49d serve one keyspace. With the
// listeners still closed it reads the seal keys and warns, writing
// nothing; loads the ledger and the marks, the process's authMarks, each
// at one revision the feeds then follow from; and on a run after a store
// gone first keeps every mark it enforced that the store lost while it was
// dark (keepLost; pre-flight 7e-2 P-1). Each read is bounded, and an outage
// is said and tried again every 5s. The ledger record is the runner's to
// keep, and the sweep is the broker's.
func openDaemon(ctx context.Context, cfg config.Config, keys crypt.Keys, m *metrics.Metrics, out io.Writer,
	again bool, gone func(error), ledger *crypt.Ledger, alarm *keyAlarm, authMarks *store.Marks,
	d *etcdstore.Store, say crypt.Option) (stores, error) {
	e := cfg.Store.Etcd
	// retry runs f until it returns anything but an outage (or one of
	// also), saying each outage and trying again in 5s with the
	// listeners closed. ctx's end ends it.
	retry := func(f func() error, also ...error) error {
		for {
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
			fmt.Fprintf(out, "port49d: %v; the listeners stay closed; trying again in 5s\n", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
			}
		}
	}
	fail := func(err error) (stores, error) {
		d.Close()
		if ctx.Err() != nil {
			return stores{}, ctx.Err()
		}
		return stores{}, err
	}
	// meta/ is the broker's to write: the daemon reads the last start's key
	// ids and warns, and the runner records them (Task 15).
	if err := retry(func() error { return checkSealKeys(ctx, d, keys, m, out, 4*e.CallTimeout, alarm, false) }); err != nil {
		return fail(err)
	}
	// The ledger (plan 7e, Rulings 3, 4), as openStores reads it with a
	// broker: the record's marks, then every live context at one revision,
	// on the daemon's raw store. A refused read of the record is roles
	// applied before plan 7e, which waiting does not mend: a store fault
	// (pre-flight M17).
	var rev uint64
	if err := retry(func() error {
		lctx, cancel := context.WithTimeout(ctx, e.BulkTimeout)
		defer cancel()
		var known, recorded int
		var err error
		rev, known, recorded, err = crypt.LoadLedger(lctx, d, d, keys, ledger)
		if err != nil {
			return fmt.Errorf("store: reading the live contexts for the ledger: %w", err)
		}
		fmt.Fprintf(out, "port49d: ledger: %d context key(s) known (%d from the ledger record); following the "+
			"store from revision %d\n", known, recorded, rev)
		return nil
	}, store.ErrCompacted); err != nil {
		if errors.Is(err, store.ErrRefused) {
			err = &storeFault{errors.New("store: the daemon's role cannot read lw/, the ledger record: apply " +
				"port49d store-roles (plan 7e) as etcd's root, then start again")}
		}
		return fail(err)
	}
	// The restore guard's two reads (final review 7e-2 M-7): a role without
	// them leaves the guard silently off on a fresh process, and refuses
	// every redemption for good once a witness was followed. A refusal is
	// roles applied by 7e-1's output or by hand, which waiting does not
	// mend: a store fault.
	if err := retry(func() error { _, err := d.RestoreRead(ctx); return err }); err != nil {
		if errors.Is(err, store.ErrRefused) {
			err = &storeFault{errors.New("store: the daemon's role cannot read meta/witness and meta/purged, " +
				"which the restore guard reads: apply port49d store-roles (plan 7e) as etcd's root, then start again")}
		}
		return fail(err)
	}
	// The marks are the process's, kept across a store gone as the ledger
	// is (Ruling 11): a run after one first keeps every mark the store lost
	// while this port49d was dark, which the load would lift otherwise, at
	// each attempt (loadDaemonMarks).
	sayKept := keptSayer(out, "as it starts again after a store gone")
	var markRev uint64
	if err := retry(func() error {
		var err error
		markRev, err = loadDaemonMarks(ctx, d, authMarks, again, e.BulkTimeout, sayKept)
		return err
	}); err != nil {
		return fail(err)
	}
	fmt.Fprintf(out, "port49d: store: %d revocation(s) in force from the store\n", authMarks.Len())
	logf := func(format string, args ...any) { fmt.Fprintf(out, "port49d: "+format+"\n", args...) }
	upOf := func(feed string) func(bool) {
		return func(up bool) { m.StoreFeedUp.WithLabelValues(feed).Set(b2f(up)) }
	}
	// Both feeds follow from the revisions read above, on the daemon's raw
	// store. The marks feed tells no one: there is no broker listener here,
	// and authMarks is what every authorization, enable and replay reads.
	// Its reload keeps what the store lost (daemonReloadHook; Ruling 5).
	follow := func(ctx context.Context) {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			crypt.FollowContexts(ctx, d, d, keys, ledger, rev, upOf("contexts"),
				func() { m.StoreFeedRescans.WithLabelValues("contexts").Inc() }, logf)
		}()
		go func() {
			defer wg.Done()
			store.FollowMarks(ctx, d, authMarks, markRev, nil, upOf("marks"),
				daemonReloadHook(ctx, d, authMarks, m.StoreFeedRescans.WithLabelValues("marks"), e.BulkTimeout, out),
				logf)
		}()
		wg.Wait()
	}
	// The daemon's raw store fenced under its guard (crypt.Fenced,
	// pre-flight C1), as openStores builds it with a broker; the probe pings
	// through the same guard, so its pings count toward the circuit that
	// ends the run, and wait for the context feed as a read does.
	gd := guard.WrapRev(crypt.Fenced(d, ledger), guardConfig(procOf(cfg), "daemon", e, m, out, gone))
	return stores{
		daemon:     crypt.Wrap(gd, keys, m.CryptOpenFailures, crypt.WithLedger(ledger), say),
		etcd:       d,
		judged:     d,
		persistent: true,
		follow:     follow,
		probe:      func(ctx context.Context) { probe(ctx, gd, e.HoldTTL/6) },
		close:      func() { d.Close() },
	}, nil
}

// guardConfig is component's guard on etcd (Task 8a): store.etcd's
// bounds and breaker, its lines on out begun with proc (procOf), and a
// pool's store failing or refusing every call for hold_ttl ending the run
// as a store gone.
func guardConfig(proc, component string, e *config.EtcdConfig, m *metrics.Metrics, out io.Writer,
	gone func(error)) guard.Config {
	return guard.Config{Proc: proc, Component: component, CallTimeout: e.CallTimeout, BulkTimeout: e.BulkTimeout,
		MaxInFlight: map[guard.Pool]int{guard.Token: e.MaxInFlight.Token, guard.Context: e.MaxInFlight.Context,
			guard.Bulk: e.MaxInFlight.Bulk},
		Failures: e.Breaker.Failures, OpenFor: e.Breaker.OpenFor, Metrics: m.StoreGuard(),
		StopAfter: e.HoldTTL, Unhealthy: func(why string) { gone(&storeGone{why: why}) },
		Say: func(l string) { fmt.Fprintln(out, l) }}
}

// b2f is 1 for true, 0 for false: a gauge's reading of a bool.
func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// unopenableSayer is crypt.OnUnopenable's line (Ruling 14): which record,
// which key id, and what to do, once per (record, key id, kind) per 10
// minutes, so a fleet of logins under a retired key is one line, not one
// per login. The kind (sayerKind) keeps the upgrade's benign line from
// silencing a put-back or tamper line under the same key id, or the
// reverse: a store writer can put a form-3 record back at any key, and
// must not be able to turn every tamper line into the upgrade's (Task 7
// review I-1).
// Each process builds one and hands it to every Wrap, so its layers share
// its memory and say a key once, not once per layer. Every line begins
// prefix, the process's name, and names it as the one that does not hold
// a key: port49d's "port49d", port49-broker's "port49-broker". It
// remembers at most sayerMax entries, and forgets them all past it: a key id
// is the record's header, which whoever writes the store chooses, so the
// memory is bounded and the cost of forgetting is one repeated line
// (pre-flight M44).
func unopenableSayer(prefix string, keys crypt.Keys, out io.Writer, now func() time.Time) func(record, keyID string, why error) {
	const sayerMax = 64
	var mu sync.Mutex
	said := map[[3]string]time.Time{}
	window := keyWindow(keys)
	return func(record, keyID string, why error) {
		mu.Lock()
		defer mu.Unlock()
		k := [3]string{record, keyID, sayerKind(why)}
		if t, ok := said[k]; ok && now().Sub(t) < 10*time.Minute {
			return
		}
		if len(said) >= sayerMax {
			clear(said)
		}
		said[k] = now()
		if keyID == "" {
			// Too short to name a key: corrupt, not a key a rotation retired
			// (review m-3).
			fmt.Fprintf(out, prefix+": crypt: a %s names no key id: it was altered or is corrupt, and is treated "+
				"as unreadable\n", record)
			return
		}
		held := keyID == keys.Current.ID || keys.Previous != nil && keyID == keys.Previous.ID
		switch {
		case held && errors.Is(why, crypt.ErrEarlierForm):
			// The upgrade, said as the upgrade: at 3am "altered" across the
			// fleet reads as an attack (pre-flight I10).
			fmt.Fprintf(out, prefix+": crypt: a %s sealed by an earlier port49 (form 3) does not open: expected once "+
				"after the 7e upgrade; replaced at its user's next login\n", record)
			return
		case held && errors.Is(why, crypt.ErrNotLastWritten):
			// It opens, and is sealed below the newest write known at its key
			// (the ledger; plan 7e, Ruling 3).
			fmt.Fprintf(out, prefix+": crypt: a %s under key id %q is sealed below the newest write any port49 "+
				"process made there: it was put back, and is treated as unreadable\n", record, keyID)
			return
		case held:
			// A held key's record that will not open was altered: its bytes
			// fail authentication.
			fmt.Fprintf(out, prefix+": crypt: a %s failed authentication under key id %q: it was altered or is "+
				"corrupt, and is treated as unreadable\n", record, keyID)
			return
		}
		fmt.Fprintf(out, prefix+": crypt: a %s is sealed under key id %q, which this "+prefix+" does not hold (%s): a "+
			"rotation retired that key while records it sealed were live; set encryption.previous to %q until they "+
			"expire\n", record, keyID, window, keyID)
	}
}

// sayerKind is which of unopenableSayer's lines why calls for, as far as
// the key id does not decide it: an earlier form, a put-back, or anything
// else.
func sayerKind(why error) string {
	switch {
	case errors.Is(why, crypt.ErrEarlierForm):
		return "earlier"
	case errors.Is(why, crypt.ErrNotLastWritten):
		return "below"
	}
	return "other"
}

// keyWindow names keys' ids for a line: "current "a", previous "b"".
func keyWindow(keys crypt.Keys) string {
	if keys.Previous != nil {
		return fmt.Sprintf("current %q, previous %q", keys.Current.ID, keys.Previous.ID)
	}
	return fmt.Sprintf("current %q, no previous", keys.Current.ID)
}

// keyAlarm is the start key check's memory for the process, kept across a
// store gone as the ledger is (review m-1, m-4). A window once warned
// keeps port49_crypt_store_key_unknown at 1 until port49d restarts: the
// records sealed under the lost key are as live after this start writes
// its own window over the store's, and a run after a store gone would
// otherwise clear the alert with nothing fixed. The stored window last
// said is not said again, through an outage's retries or a run after one.
// One start uses it at a time.
type keyAlarm struct {
	raised bool
	said   *storedWindow // nil before any is said
}

// storedWindow is a window the store held, as keyAlarm remembers it.
type storedWindow struct {
	undecodable       bool
	current, previous string
}

func newKeyAlarm() *keyAlarm { return &keyAlarm{} }

// warn raises the alarm for w and says it once per stored window.
func (a *keyAlarm) warn(w storedWindow, say func()) {
	a.raised = true
	if a.said != nil && *a.said == w {
		return
	}
	a.said = &w
	say()
}

// checkSealKeys is the start's key check on etcd (Ruling 14): a store last
// written under a current key this window lacks is said, and gauged, and
// never refuses the start; then this window is recorded. A last window
// that does not decode is said and gauged the same, never echoed, and
// written over: a refused start would hand whoever can write the store a
// lockout of every start. Only an outage is returned, a call past bound
// among them. alarm is the process's (keyAlarm). With write false it
// writes nothing: port49d with no broker reads the record and warns, and
// its role cannot write meta/ (plan 7e). Its lines are port49d's
// (checkSealKeysAs).
func checkSealKeys(ctx context.Context, s *etcdstore.Store, keys crypt.Keys, m *metrics.Metrics, out io.Writer,
	bound time.Duration, alarm *keyAlarm, write bool) error {
	return checkSealKeysAs(ctx, "port49d", s, keys, m, out, bound, alarm, write)
}

// checkSealKeysAs is checkSealKeys with proc, the process's name, leading
// its lines and naming the process that does not hold a key:
// port49-broker's runner writes the record (plan 7e, Ruling 6).
func checkSealKeysAs(ctx context.Context, proc string, s *etcdstore.Store, keys crypt.Keys, m *metrics.Metrics,
	out io.Writer, bound time.Duration, alarm *keyAlarm, write bool) error {
	rctx, cancel := context.WithTimeout(ctx, bound)
	last, ok, err := s.SealKeys(rctx)
	cancel()
	undecodable := errors.Is(err, etcdstore.ErrSealKeysUndecodable)
	if err != nil && !undecodable {
		return fmt.Errorf("store: reading the last start's key ids: %w", err)
	}
	held := !ok || last.Current == keys.Current.ID || keys.Previous != nil && last.Current == keys.Previous.ID
	if undecodable {
		over := "; this start's are written over it"
		if !write {
			over = ""
		}
		alarm.warn(storedWindow{undecodable: true}, func() {
			fmt.Fprintf(out, "%s: crypt: the last start's key ids are unreadable (meta/seal_keys does not "+
				"decode), so records may be sealed under a key this %s does not hold (%s); any that are are "+
				"denied store_unavailable, and %s says each key id as it meets one%s\n", proc, proc, keyWindow(keys),
				proc, over)
		})
	} else if !held {
		id := crypt.LineKeyID(last.Current)
		alarm.warn(storedWindow{current: last.Current, previous: last.Previous}, func() {
			// Said before the start carries the policy into the kept contexts,
			// which leaves every one under an unheld key unjudged, never
			// revoked (refresh.go, ErrLeftUnderUnheldKey; spec, a start on
			// etcd, Keys): so it says they are denied until a start holds the
			// key, and that fixing it brings them back. Tokens are purged at
			// every start on etcd, so none is named.
			fmt.Fprintf(out, "%s: crypt: the store was last written by a port49 process whose current key is %q, "+
				"which this configuration does not hold (%s); the live sessions sealed under %q cannot be read, "+
				"and are denied store_unavailable until a start holds that key again; none is revoked for it: "+
				"if %q was retired by mistake, set encryption.previous to %q and start %s again\n",
				proc, id, keyWindow(keys), id, id, id, proc)
		})
	}
	m.CryptStoreKeyUnknown.Set(0)
	if alarm.raised {
		m.CryptStoreKeyUnknown.Set(1)
	}
	if !write {
		return nil
	}
	cur := etcdstore.SealKeys{Current: keys.Current.ID, WrittenAt: time.Now().UTC()}
	if keys.Previous != nil {
		cur.Previous = keys.Previous.ID
	}
	pctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	return s.PutSealKeys(pctx, cur)
}

// attempt is one try at the store, as a start-wait loop runs it
// (pre-flight I9, I13, M33), on the one identity cfg's role names: the
// daemon's for port49d, the broker's for port49-broker (plan 7e, Ruling
// 1):
//  1. load the identity through keyfile, and check its validity and the
//     CA's;
//  2. probe the TLS handshake;
//  3. open the store, ping, and check the role.
//
// An outage is store.ErrUnavailable; a configuration fault is a
// *storeFault naming what is wrong. Each start says the certificate's
// expiry, once it succeeds.
func attempt(ctx context.Context, cfg config.Config, m *metrics.Metrics, out io.Writer) (*etcdstore.Store, error) {
	e := cfg.Store.Etcd
	now := time.Now()
	pool, cas, err := caCerts(e.CAFile)
	if err != nil {
		return nil, &storeFault{fmt.Errorf("store.etcd.ca_file %s: %w", e.CAFile, err)}
	}
	for _, ca := range cas {
		if now.After(ca.NotAfter) || now.Before(ca.NotBefore) {
			return nil, &storeFault{fmt.Errorf("store.etcd.ca_file %s: CA %s is valid only from %s to %s; "+
				"replace it", e.CAFile, ca.Subject, ca.NotBefore.UTC().Format(time.RFC3339), ca.NotAfter.UTC().Format(time.RFC3339))}
		}
	}
	name, id := "daemon", e.Daemon
	if cfg.Role == config.RoleBroker {
		name, id = "broker", *e.Broker
	}
	s, leaf, err := openIdentity(ctx, cfg, m, out, pool, now, name, id)
	if err != nil {
		return nil, err
	}
	pctx, cancel := context.WithTimeout(ctx, 4*e.CallTimeout)
	err = s.Ping(pctx)
	cancel()
	if err == nil {
		leaves := map[string]*x509.Certificate{name: leaf}
		if name == "broker" {
			err = checkRoles(ctx, nil, s, e, leaves)
		} else {
			err = checkRoles(ctx, s, nil, e, leaves)
		}
	}
	if err != nil {
		s.Close()
		if errors.Is(err, store.ErrUnavailable) {
			return nil, err
		}
		return nil, &storeFault{err}
	}
	m.StoreCertExpiry.WithLabelValues(name).Set(float64(leaf.NotAfter.Unix()))
	fmt.Fprintf(out, "%s: store: the %s's etcd certificate (CN=%s) is valid until %s (%d days)\n", procOf(cfg), name,
		leaf.Subject.CommonName, leaf.NotAfter.UTC().Format(time.RFC3339), int(leaf.NotAfter.Sub(now).Hours()/24))
	return s, nil
}

// openIdentity opens the store as one component's identity, name in
// store.etcd: its certificate loaded and checked (identity) against pool
// at now, and its TLS handshake probed (probeTLS). What the etcd store
// skips, it says by key alone on out and counts (Task 7 review m-5): the
// process's lines, and port49_store_index_records_undecodable_total.
func openIdentity(ctx context.Context, cfg config.Config, m *metrics.Metrics, out io.Writer, pool *x509.CertPool,
	now time.Time, name string, id config.EtcdIdentity) (*etcdstore.Store, *x509.Certificate, error) {
	e := cfg.Store.Etcd
	tc, leaf, err := identity(name, id, pool, now)
	if err != nil {
		return nil, nil, err
	}
	if err := probeTLS(ctx, e.Endpoints, tc, 4*e.CallTimeout); err != nil {
		return nil, nil, err
	}
	proc := procOf(cfg)
	logf := func(format string, args ...any) { fmt.Fprintf(out, proc+": store: "+format+"\n", args...) }
	s, err := etcdstore.Open(etcdstore.Config{Endpoints: e.Endpoints, Prefix: e.Prefix, LeaseGrace: e.LeaseGrace,
		TLS: tc, Logf: logf, IndexUndecodable: m.IndexRecordsUndecodable})
	if err != nil {
		return nil, nil, &storeFault{fmt.Errorf("store.etcd.%s: %w", name, err)}
	}
	return s, leaf, nil
}

// identity loads one component's client certificate through keyfile,
// which refuses a symlink, a mode group or other can read, a foreign
// owner and an oversize file, all at the read (pre-flight I13). A
// certificate that does not parse is refused naming both files (Task
// 11), and so is one whose CN is etcd's root (Ruling T11-a). It then
// checks the leaf's validity window against now (I9). An expired or
// not-yet-valid certificate is a storeFault naming the file, the CN and
// the instant, never "not answering".
func identity(name string, id config.EtcdIdentity, pool *x509.CertPool, now time.Time) (*tls.Config, *x509.Certificate, error) {
	pair, err := keyfile.LoadX509KeyPair(id.CertFile, id.KeyFile)
	if err != nil {
		return nil, nil, &storeFault{fmt.Errorf("store.etcd.%s (cert_file %s, key_file %s): %w", name, id.CertFile,
			id.KeyFile, err)}
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, &storeFault{fmt.Errorf("store.etcd.%s: certificate %s, for key_file %s, does not parse: %w",
			name, id.CertFile, id.KeyFile, err)}
	}
	switch {
	case leaf.Subject.CommonName == etcdstore.RootUser:
		return nil, nil, &storeFault{fmt.Errorf("store.etcd.%s: certificate %s: its CN is %q, etcd's administrator, "+
			"which bypasses every role: give the component a certificate of its own", name, id.CertFile,
			etcdstore.RootUser)}
	case now.After(leaf.NotAfter):
		return nil, nil, &storeFault{fmt.Errorf("store.etcd.%s: certificate %s (CN=%s) expired at %s; renew it", name,
			id.CertFile, leaf.Subject.CommonName, leaf.NotAfter.UTC().Format(time.RFC3339))}
	case now.Before(leaf.NotBefore):
		return nil, nil, &storeFault{fmt.Errorf("store.etcd.%s: certificate %s (CN=%s) is not valid until %s; check "+
			"this host's clock", name, id.CertFile, leaf.Subject.CommonName, leaf.NotBefore.UTC().Format(time.RFC3339))}
	}
	return &tls.Config{RootCAs: pool, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, leaf, nil
}

// probeTLS completes a TLS handshake with each endpoint in turn as the
// component, then reads once, briefly (pre-flight I9). Under TLS 1.3 etcd
// refuses a client certificate after the handshake, with an alert on the
// first read, and clientv3 would report that only as a deadline. So:
//   - a certificate the server refuses, or a server certificate this CA
//     does not verify, is a storeFault naming it;
//   - an endpoint that does not answer is store.ErrUnavailable;
//   - one endpoint that completes is enough.
func probeTLS(ctx context.Context, endpoints []string, tc *tls.Config, timeout time.Duration) error {
	var last error
	for _, ep := range endpoints {
		u, err := url.Parse(ep)
		if err != nil {
			return &storeFault{fmt.Errorf("store.etcd.endpoints %q: %w", ep, err)}
		}
		dctx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := (&tls.Dialer{Config: tc}).DialContext(dctx, "tcp", u.Host)
		cancel()
		if err != nil {
			if tlsFault(err) {
				return &storeFault{fmt.Errorf("etcd at %s: the TLS handshake failed: %w", ep, err)}
			}
			last = err
			continue
		}
		conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		_, rerr := conn.Read(make([]byte, 1))
		conn.Close()
		if rerr != nil && tlsFault(rerr) {
			return &storeFault{fmt.Errorf("etcd at %s refused this certificate: %w", ep, rerr)}
		}
		return nil
	}
	return fmt.Errorf("%w: %v", store.ErrUnavailable, last)
}

// tlsFault is an error about the certificates, not the network: an alert
// the server sent (crypto/tls spells it "remote error: tls: …"; its type
// is unexported, as the agent's certificateAlerts says), or a chain this
// side would not verify.
func tlsFault(err error) bool {
	var verr *tls.CertificateVerificationError
	var uerr x509.UnknownAuthorityError
	var herr x509.HostnameError
	return errors.As(err, &verr) || errors.As(err, &uerr) || errors.As(err, &herr) ||
		strings.Contains(err.Error(), "remote error: tls:")
}

// checkRoles is Ruling 10's start check, its refusal naming the identity
// and the fix. Under store.etcd.roles: unenforced the daemon's is not run,
// since its roles are not in force by the operator's choice; the broker's
// still is, so neither identity is etcd's root and the broker's reach is
// whole (Task 11). Each process holds one identity (plan 7e): d is nil on
// port49-broker, and b on port49d.
func checkRoles(ctx context.Context, d, b *etcdstore.Store, e *config.EtcdConfig, leaves map[string]*x509.Certificate) error {
	cctx, cancel := context.WithTimeout(ctx, 4*e.CallTimeout)
	defer cancel()
	if d != nil && e.Roles != config.RolesUnenforced {
		if err := d.CheckIdentity(cctx, false); err != nil {
			if errors.Is(err, etcdstore.ErrNotSeparated) {
				return fmt.Errorf("store.etcd.daemon: its identity (CN=%s): %w: etcd's roles for port49 are not in force "+
					"(auth disabled, or that user holds the broker's or root's role); run 'port49d store-roles --config …' "+
					"and apply its output as etcd's root, or set store.etcd.roles: unenforced to run without them",
					leaves["daemon"].Subject.CommonName, err)
			}
			return fmt.Errorf("store.etcd.daemon: its identity (CN=%s): %w", leaves["daemon"].Subject.CommonName, err)
		}
	}
	if b == nil {
		return nil
	}
	if err := b.CheckIdentity(cctx, true); err != nil {
		return fmt.Errorf("store.etcd.broker: its identity (CN=%s): %w; give the broker an etcd user of its own and "+
			"apply 'port49d store-roles' output", leaves["broker"].Subject.CommonName, err)
	}
	return nil
}

// caCerts is the CA file's certificates, and a pool of them.
func caCerts(path string) (*x509.CertPool, []*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, raw = pem.Decode(raw)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, nil, err
		}
		pool.AddCert(c)
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, nil, errors.New("no certificate in it")
	}
	return pool, out, nil
}

// sweepLoop runs the index sweep every interval (Ruling 6), then finds
// the contexts the index lost and has the broker re-index and judge them
// (re-check IA2), saying only a failure. ReindexContexts says what it
// found. Each half has half the interval of its own, so a slow sweep
// cannot starve the re-index (pre-flight re-check 2 M-B5). After each, it
// prunes the ledger's marks past their keep (crypt.Ledger.Prune).
func sweepLoop(ctx context.Context, s *etcdstore.Store, brk *broker.Broker, ledger *crypt.Ledger,
	every time.Duration, out io.Writer) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		sctx, cancel := context.WithTimeout(ctx, every/2)
		if _, _, err := s.Sweep(sctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(out, "port49-broker: runner: the index sweep did not finish (%v); it runs again in %v\n", err, every)
		}
		cancel()
		uctx, cancel := context.WithTimeout(ctx, every/2)
		refs, err := s.Unindexed(uctx)
		if err == nil {
			_, err = brk.ReindexContexts(uctx, refs)
		}
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(out, "port49-broker: runner: finding the contexts the index lost did not finish (%v); it runs again "+
				"in %v\n", err, every)
		}
		cancel()
		ledger.Prune(time.Now())
	}
}

// ledgerPruneEvery is how often pruneLoop prunes the ledger where no sweep
// runs: on the memory store, and on port49d beside port49-broker.
const ledgerPruneEvery = 10 * time.Minute

// pruneLoop prunes the ledger's marks past their keep every interval
// until ctx ends: sweepLoop's prune, where no sweep runs.
func pruneLoop(ctx context.Context, ledger *crypt.Ledger, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ledger.Prune(time.Now())
		}
	}
}
