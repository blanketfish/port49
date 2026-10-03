package main

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

// holderShape is the holder port49d writes under meta/hold (openStores).
var holderShape = regexp.MustCompile(`^port49d on [A-Za-z0-9._-]{0,253} \(pid [0-9]{1,10}, since [0-9TZ:+.-]{1,40}\)$`)

// lineHolder is meta/holder as a line may echo it: quoted and cut to 200
// bytes in the shape port49d writes, "?" otherwise. Whoever can write
// meta/ writes it, and a line must not carry its newlines or a megabyte
// of it (final review 7d-2 m-1).
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
// on etcd the daemon's and the broker's, each its own identity, guard and
// sealing layer; on memory one store for both.
type stores struct {
	daemon, broker store.Store
	// etcd is the daemon's backend, for the sweep. Nil on memory.
	etcd       *etcdstore.Store
	persistent bool
	// lost is closed when this port49d loses its hold on the keyspace;
	// nil on memory, where nothing is lost.
	lost <-chan struct{}
	// follow keeps the ledger following the store's contexts until its
	// ctx ends (crypt.FollowContexts). runOnce runs it as soon as the stores
	// are open, and joins it before close. Nil on memory, where every write
	// is this process's own.
	follow func(ctx context.Context)
	// keep writes the ledger's raised marks to the ledger record until its
	// ctx ends (crypt.KeepLedger; plan 7e, Ruling 4): in 7e-1 port49d holds
	// the keyspace, so it keeps the record, with the broker's identity.
	// runOnce runs and joins it as it does follow. Nil on memory, where
	// there is no record.
	keep  func(ctx context.Context)
	close func()
}

// storeGone ends one run of port49d on etcd (Ruling 11; pre-flight I10,
// I19): the hold was lost, or a pool's store has failed or refused every
// call for hold_ttl. run then starts the next, which waits for the store
// with every listener closed, as at a start.
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
// no deadline when again says this run follows a store gone. Then it
// takes the hold, waiting for another port49d to let go. gone is how the
// guard ends the run. It says each step on out. held is the holder this
// process's last hold was taken as, kept across runs: a hold lost when the
// store stopped answering leaves its lease to expire, so the next run
// waits on this process's own last run, and says so (final review 7d-2
// I-2). openStores sets it once it holds the keyspace.
func openStores(ctx context.Context, cfg config.Config, keys crypt.Keys, m *metrics.Metrics, out io.Writer,
	rd *readiness, again bool, gone func(error), ledger *crypt.Ledger, alarm *keyAlarm, held *string) (stores, error) {
	// One sayer for every layer, so a key is said once, not once per layer
	// (pre-flight M44).
	say := crypt.OnUnopenable(unopenableSayer(keys, out, time.Now))
	if cfg.Store.Backend != config.BackendEtcd {
		// The memory store is new and empty: every record in it is sealed
		// above its base (crypt.Ledger).
		mem := memory.New(time.Now)
		ledger.SetBase(mem.Seen() + 1)
		st := crypt.Wrap(mem, keys, m.CryptOpenFailures, crypt.WithLedger(ledger), say)
		return stores{daemon: st, broker: st, close: func() {}}, nil
	}
	e := cfg.Store.Etcd
	// A run after a store gone shows the alarm a run before raised from
	// its first scrape: the wait below is the outage, and a gauge at 0
	// through it would resolve the alert (keyAlarm; re-review I-3).
	if alarm.raised {
		m.CryptStoreKeyUnknown.Set(1)
	}
	rd.set(readyStore)
	eps := strings.Join(e.Endpoints, ", ")
	var deadline time.Time
	if !again && e.StartTimeout > 0 {
		deadline = time.Now().Add(e.StartTimeout)
	}
	var d, b *etcdstore.Store
	for {
		var err error
		d, b, err = attempt(ctx, cfg, m, out)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return stores{}, ctx.Err()
		}
		var fault *storeFault
		switch {
		case errors.As(err, &fault) && !again:
			return stores{}, err // the operator's to fix; named, exit 1
		case errors.As(err, &fault):
			fmt.Fprintf(out, "port49d: %v; the listeners stay closed; trying again in 5s\n", err)
		case !deadline.IsZero() && time.Now().After(deadline):
			return stores{}, fmt.Errorf("store: etcd at %s did not answer within store.etcd.start_timeout (%v); not "+
				"starting", eps, e.StartTimeout)
		default:
			wait := "until it answers"
			if !deadline.IsZero() {
				wait = fmt.Sprintf("up to %v", e.StartTimeout)
			}
			fmt.Fprintf(out, "port49d: store: etcd at %s not answering (%v); the listeners stay closed; waiting %s\n",
				eps, err, wait)
		}
		select {
		case <-ctx.Done():
			return stores{}, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	closeAll := func() { b.Close(); d.Close() }
	if e.Roles == config.RolesUnenforced {
		fmt.Fprintln(out, "port49d: store.etcd.roles: unenforced: the daemon and the broker are not separated on etcd; "+
			"a stolen daemon key can lift revocations")
	}
	host, _ := os.Hostname()
	who := fmt.Sprintf("port49d on %s (pid %d, since %s)", host, os.Getpid(), time.Now().UTC().Format(time.RFC3339))
	m.StoreKeyspaceHeld.Set(0)
	var lost <-chan struct{}
	var release func()
	for {
		var err error
		lost, release, err = b.Hold(ctx, e.HoldTTL, who, func(holder string) {
			if *held != "" && holder == *held {
				fmt.Fprintf(out, "port49d: store: keyspace %s is still held by this port49d's last run (its hold "+
					"was lost when the store stopped answering); waiting up to hold_ttl (%v) for its lease to "+
					"expire, with the listeners closed\n", e.Prefix, e.HoldTTL)
				return
			}
			fmt.Fprintf(out, "port49d: store: keyspace %s is held by %s; waiting, with the listeners closed: one "+
				"port49d per keyspace until plan 7e; stop that port49d to move the keyspace, and never delete "+
				"meta/hold\n", e.Prefix, lineHolder(holder))
		})
		if err == nil {
			*held = who
			break
		}
		if ctx.Err() != nil || !errors.Is(err, store.ErrUnavailable) {
			closeAll()
			if ctx.Err() != nil {
				return stores{}, ctx.Err()
			}
			return stores{}, fmt.Errorf("store: taking keyspace %s: %w", e.Prefix, err)
		}
		fmt.Fprintf(out, "port49d: store: taking keyspace %s: %v; the listeners stay closed; trying again in 5s\n",
			e.Prefix, err)
		select {
		case <-ctx.Done():
			closeAll()
			return stores{}, ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	m.StoreKeyspaceHeld.Set(1)
	// meta/ is the broker's to write (Task 11), so the key check is its.
	// Each of its calls is bounded as the ping is, so a store that stops
	// answering here is said and tried again, not a silent hang with the
	// hold kept (review I-1); a hold lost meanwhile ends the start as a
	// store gone, letting it go.
	letGo := func() { release(); m.StoreKeyspaceHeld.Set(0); closeAll() }
	for {
		err := checkSealKeys(ctx, b, keys, m, out, 4*e.CallTimeout, alarm)
		if err == nil {
			break
		}
		if ctx.Err() != nil || !errors.Is(err, store.ErrUnavailable) {
			letGo()
			if ctx.Err() != nil {
				return stores{}, ctx.Err()
			}
			return stores{}, err
		}
		fmt.Fprintf(out, "port49d: %v; the listeners stay closed; trying again in 5s\n", err)
		select {
		case <-ctx.Done():
			letGo()
			return stores{}, ctx.Err()
		case <-lost:
			letGo()
			return stores{}, &storeGone{why: fmt.Sprintf("lost this port49d's hold on keyspace %s while "+
				"checking the store's key ids", e.Prefix)}
		case <-time.After(5 * time.Second):
		}
	}
	// The ledger (plan 7e, Rulings 3, 4): every mark the ledger record
	// holds, then every live context at one revision, both read on the
	// daemon's raw store, which the feed then follows from that revision.
	// The base is just past it before anything reads a context, the
	// start's reads included. An outage is said and tried again as the key
	// check is. A refused read of the record is roles applied before plan
	// 7e, which waiting does not mend: a store fault (pre-flight M17).
	var rev uint64
	for {
		lctx, cancel := context.WithTimeout(ctx, e.BulkTimeout)
		var known, recorded int
		var err error
		rev, known, recorded, err = crypt.LoadLedger(lctx, d, d, keys, ledger)
		cancel()
		if err == nil {
			fmt.Fprintf(out, "port49d: ledger: %d context key(s) known (%d from the ledger record); following the "+
				"store from revision %d\n", known, recorded, rev)
			break
		}
		if ctx.Err() != nil || !errors.Is(err, store.ErrUnavailable) && !errors.Is(err, store.ErrCompacted) {
			letGo()
			switch {
			case ctx.Err() != nil:
				return stores{}, ctx.Err()
			case errors.Is(err, store.ErrRefused):
				return stores{}, &storeFault{errors.New("store: the daemon's role cannot read lw/, the ledger " +
					"record: apply port49d store-roles (plan 7e) as etcd's root, then start again")}
			}
			return stores{}, fmt.Errorf("store: reading the live contexts for the ledger: %w", err)
		}
		fmt.Fprintf(out, "port49d: store: reading the live contexts for the ledger: %v; the listeners stay closed; "+
			"trying again in 5s\n", err)
		select {
		case <-ctx.Done():
			letGo()
			return stores{}, ctx.Err()
		case <-lost:
			letGo()
			return stores{}, &storeGone{why: fmt.Sprintf("lost this port49d's hold on keyspace %s while "+
				"reading the live contexts for the ledger", e.Prefix)}
		case <-time.After(5 * time.Second):
		}
	}
	follow := func(ctx context.Context) {
		crypt.FollowContexts(ctx, d, d, keys, ledger, rev,
			func(up bool) {
				v := 0.0
				if up {
					v = 1
				}
				m.StoreFeedUp.WithLabelValues("contexts").Set(v)
			},
			func() { m.StoreFeedRescans.WithLabelValues("contexts").Inc() },
			func(format string, args ...any) { fmt.Fprintf(out, "port49d: "+format+"\n", args...) })
	}
	keep := func(ctx context.Context) {
		crypt.KeepLedger(ctx, ledger, b, time.Second, func(n int, behind bool) {
			m.LedgerPending.Set(float64(n))
			m.LedgerBehind.Set(b2f(behind))
		}, func(format string, args ...any) { fmt.Fprintf(out, "port49d: "+format+"\n", args...) })
	}
	gc := func(component string) guard.Config {
		return guard.Config{Component: component, CallTimeout: e.CallTimeout, BulkTimeout: e.BulkTimeout,
			MaxInFlight: map[guard.Pool]int{guard.Token: e.MaxInFlight.Token, guard.Context: e.MaxInFlight.Context,
				guard.Bulk: e.MaxInFlight.Bulk},
			Failures: e.Breaker.Failures, OpenFor: e.Breaker.OpenFor, Metrics: m.StoreGuard(),
			StopAfter: e.HoldTTL, Unhealthy: func(why string) { gone(&storeGone{why: why}) },
			Say: func(l string) { fmt.Fprintln(out, l) }}
	}
	// One ledger for both layers (re-check IA1): the broker's reads at
	// start seed it for the daemon's, and either denies another login's
	// context written back. Each raw store is fenced under its guard
	// (crypt.Fenced, pre-flight C1): a context read waits, within
	// call_timeout, for the feed to pass the record's revision. The raw
	// stores the sweep, the hold and the record use read no context for
	// admission and stay unfenced.
	return stores{
		daemon: crypt.Wrap(guard.WrapRev(crypt.Fenced(d, ledger), gc("daemon")), keys, m.CryptOpenFailures,
			crypt.WithLedger(ledger), say),
		broker: crypt.Wrap(guard.WrapRev(crypt.Fenced(b, ledger), gc("broker")), keys, m.CryptOpenFailures,
			crypt.WithLedger(ledger), say),
		etcd:       d,
		persistent: true,
		lost:       lost,
		follow:     follow,
		keep:       keep,
		close:      func() { release(); m.StoreKeyspaceHeld.Set(0); closeAll() },
	}, nil
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
// openStores builds one and hands it to every Wrap, so the daemon's and
// the broker's layers share its memory and say a key once, not twice. It
// remembers at most sayerMax entries, and forgets them all past it: a key id
// is the record's header, which whoever writes the store chooses, so the
// memory is bounded and the cost of forgetting is one repeated line
// (pre-flight M44).
func unopenableSayer(keys crypt.Keys, out io.Writer, now func() time.Time) func(record, keyID string, why error) {
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
			fmt.Fprintf(out, "port49d: crypt: a %s names no key id: it was altered or is corrupt, and is treated "+
				"as unreadable\n", record)
			return
		}
		held := keyID == keys.Current.ID || keys.Previous != nil && keyID == keys.Previous.ID
		switch {
		case held && errors.Is(why, crypt.ErrEarlierForm):
			// The upgrade, said as the upgrade: at 3am "altered" across the
			// fleet reads as an attack (pre-flight I10).
			fmt.Fprintf(out, "port49d: crypt: a %s sealed by an earlier port49 (form 3) does not open: expected once "+
				"after the 7e upgrade; replaced at its user's next login\n", record)
			return
		case held && errors.Is(why, crypt.ErrNotLastWritten):
			// It opens, and is sealed below the newest write known at its key
			// (the ledger; plan 7e, Ruling 3).
			fmt.Fprintf(out, "port49d: crypt: a %s under key id %q is sealed below the newest write any port49 "+
				"process made there: it was put back, and is treated as unreadable\n", record, keyID)
			return
		case held:
			// A held key's record that will not open was altered: its bytes
			// fail authentication.
			fmt.Fprintf(out, "port49d: crypt: a %s failed authentication under key id %q: it was altered or is "+
				"corrupt, and is treated as unreadable\n", record, keyID)
			return
		}
		fmt.Fprintf(out, "port49d: crypt: a %s is sealed under key id %q, which this port49d does not hold (%s): a "+
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
// among them. alarm is the process's (keyAlarm).
func checkSealKeys(ctx context.Context, s *etcdstore.Store, keys crypt.Keys, m *metrics.Metrics, out io.Writer,
	bound time.Duration, alarm *keyAlarm) error {
	rctx, cancel := context.WithTimeout(ctx, bound)
	last, ok, err := s.SealKeys(rctx)
	cancel()
	undecodable := errors.Is(err, etcdstore.ErrSealKeysUndecodable)
	if err != nil && !undecodable {
		return fmt.Errorf("store: reading the last start's key ids: %w", err)
	}
	held := !ok || last.Current == keys.Current.ID || keys.Previous != nil && last.Current == keys.Previous.ID
	if undecodable {
		alarm.warn(storedWindow{undecodable: true}, func() {
			fmt.Fprintf(out, "port49d: crypt: the last start's key ids are unreadable (meta/seal_keys does not "+
				"decode), so records may be sealed under a key this port49d does not hold (%s); any that are are "+
				"denied store_unavailable, and port49d says each key id as it meets one; this start's are written "+
				"over it\n", keyWindow(keys))
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
			fmt.Fprintf(out, "port49d: crypt: the store was last written by a port49d whose current key is %q, "+
				"which this configuration does not hold (%s); the live sessions sealed under %q cannot be read, "+
				"and are denied store_unavailable until a start holds that key again; none is revoked for it: "+
				"if %q was retired by mistake, set encryption.previous to %q and start port49d again\n",
				id, keyWindow(keys), id, id, id)
		})
	}
	m.CryptStoreKeyUnknown.Set(0)
	if alarm.raised {
		m.CryptStoreKeyUnknown.Set(1)
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
// (pre-flight I9, I13, M33):
//  1. load each identity through keyfile, and check its validity and the
//     CA's;
//  2. probe the TLS handshake;
//  3. open both stores, ping, and check the roles.
//
// An outage is store.ErrUnavailable; a configuration fault is a
// *storeFault naming what is wrong. Each start says each certificate's
// expiry, once it succeeds.
func attempt(ctx context.Context, cfg config.Config, m *metrics.Metrics, out io.Writer) (d, b *etcdstore.Store, err error) {
	e := cfg.Store.Etcd
	now := time.Now()
	pool, cas, err := caCerts(e.CAFile)
	if err != nil {
		return nil, nil, &storeFault{fmt.Errorf("store.etcd.ca_file %s: %w", e.CAFile, err)}
	}
	for _, ca := range cas {
		if now.After(ca.NotAfter) || now.Before(ca.NotBefore) {
			return nil, nil, &storeFault{fmt.Errorf("store.etcd.ca_file %s: CA %s is valid only from %s to %s; "+
				"replace it", e.CAFile, ca.Subject, ca.NotBefore.UTC().Format(time.RFC3339), ca.NotAfter.UTC().Format(time.RFC3339))}
		}
	}
	// What the etcd store skips, it says by key alone and counts (Task 7
	// review m-5): port49d's lines, and port49_store_index_records_undecodable_total.
	logf := func(format string, args ...any) { fmt.Fprintf(out, "port49d: store: "+format+"\n", args...) }
	leaves := map[string]*x509.Certificate{}
	open := func(name string, id config.EtcdIdentity) (*etcdstore.Store, error) {
		tc, leaf, err := identity(name, id, pool, now)
		if err != nil {
			return nil, err
		}
		if err := probeTLS(ctx, e.Endpoints, tc, 4*e.CallTimeout); err != nil {
			return nil, err
		}
		s, err := etcdstore.Open(etcdstore.Config{Endpoints: e.Endpoints, Prefix: e.Prefix, LeaseGrace: e.LeaseGrace,
			TLS: tc, Logf: logf, IndexUndecodable: m.IndexRecordsUndecodable})
		if err != nil {
			return nil, &storeFault{fmt.Errorf("store.etcd.%s: %w", name, err)}
		}
		leaves[name] = leaf
		return s, nil
	}
	if d, err = open("daemon", e.Daemon); err != nil {
		return nil, nil, err
	}
	if b, err = open("broker", *e.Broker); err != nil {
		d.Close()
		return nil, nil, err
	}
	pctx, cancel := context.WithTimeout(ctx, 4*e.CallTimeout)
	err = d.Ping(pctx)
	cancel()
	if err == nil {
		err = checkRoles(ctx, d, b, e, leaves)
	}
	if err != nil {
		b.Close()
		d.Close()
		if errors.Is(err, store.ErrUnavailable) {
			return nil, nil, err
		}
		return nil, nil, &storeFault{err}
	}
	for _, name := range []string{"daemon", "broker"} {
		leaf := leaves[name]
		m.StoreCertExpiry.WithLabelValues(name).Set(float64(leaf.NotAfter.Unix()))
		fmt.Fprintf(out, "port49d: store: the %s's etcd certificate (CN=%s) is valid until %s (%d days)\n", name,
			leaf.Subject.CommonName, leaf.NotAfter.UTC().Format(time.RFC3339), int(leaf.NotAfter.Sub(now).Hours()/24))
	}
	return d, b, nil
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
// whole (Task 11).
func checkRoles(ctx context.Context, d, b *etcdstore.Store, e *config.EtcdConfig, leaves map[string]*x509.Certificate) error {
	cctx, cancel := context.WithTimeout(ctx, 4*e.CallTimeout)
	defer cancel()
	if e.Roles != config.RolesUnenforced {
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

// refreshOwed is the refresh pass a start on a persistent store leaves
// the reloader: none, or one at once (a context still changing; Ruling
// T12-d) or at the next retry (a context under an unheld key; T12-a).
// Either way port49_policy_refresh_pending is 1 until a pass completes.
type refreshOwed struct {
	owed bool
	now  bool
}

// startLeftBy is what the start does with what its carry left
// (RefreshAtStart). An outage, or a principal whose contexts could not be
// looked up, holds it: again is that error, which the carry's retry waits
// on, running it again with the listeners closed (Ruling T12-c). A
// context still changing opens it owing a pass as soon as the listeners
// are open (Ruling T12-d); one under an unheld key opens it owing the next
// retry, since every path denies it meanwhile (Ruling T12-a). Any other
// error is again as well, and ends the start.
func startLeftBy(err error) (owed refreshOwed, again error) {
	switch {
	case err == nil:
		return refreshOwed{}, nil
	case errors.Is(err, store.ErrUnavailable), errors.Is(err, broker.ErrPrincipalUnvisited):
		return refreshOwed{}, err
	case errors.Is(err, broker.ErrLeftUnderUnheldKey):
		return refreshOwed{owed: true}, nil
	case errors.Is(err, store.ErrConflict):
		return refreshOwed{owed: true, now: true}, nil
	}
	return refreshOwed{}, err
}

// startOnPersistentStore is a start on etcd after the file's marks are
// restored (decision 35, a start on etcd; Ruling 12; Ruling 13;
// pre-flight C1, M41; re-check IA2). With the listeners still closed, it:
//  1. puts the store's marks the file lacked in force and saves them to
//     it, counted as a set difference on (kind, key);
//  2. re-indexes every kept context the index lost (e.Unindexed, then
//     ReindexContexts), so the passes below reach it;
//  3. applies every standing mark to the live contexts the store kept,
//     by 7a's two context passes;
//  4. purges every unspent token and supersedes every key;
//  5. carries the policy in force into every live context the store
//     kept.
//
// The ledger's base was set before any of it, just past openStores's scan
// of the contexts (crypt.LoadLedger), and the feed follows from there
// (plan 7e, Ruling 3).
//
// Each step that reads the store retries every 5s while it errs, and so
// does step 5 while a principal's contexts cannot be looked up (Ruling
// T12-c). What step 5 leaves otherwise opens the start, owing a pass
// (refreshOwed). marks ends as every mark in force, which the caller puts
// in the daemon's marks and the listener's.
func startOnPersistentStore(ctx context.Context, brk *broker.Broker, st store.Store, e *etcdstore.Store,
	cfg config.Config, marks *[]store.Revocation, m *metrics.Metrics) (refreshOwed, error) {
	retry := func(what string, f func() error, also ...error) error {
		for {
			err := f()
			if err == nil {
				return nil
			}
			wait := errors.Is(err, store.ErrUnavailable)
			for _, a := range also {
				wait = wait || errors.Is(err, a)
			}
			if !wait {
				return fmt.Errorf("store: %s: %w", what, err)
			}
			fmt.Fprintf(stderr, "port49d: store: %s: %v; the listeners stay closed; trying again in 5s\n", what, err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(5 * time.Second):
			}
		}
	}
	var all []store.Revocation
	if err := retry("listing the revocations in force", func() (err error) {
		all, err = st.ListRevocations(ctx)
		return err
	}); err != nil {
		return refreshOwed{}, err
	}
	inFile := map[[2]string]bool{}
	for _, r := range *marks {
		inFile[[2]string{r.Kind, r.Key}] = true
	}
	extra := 0
	for _, r := range all {
		if !inFile[[2]string{r.Kind, r.Key}] {
			extra++
		}
	}
	if extra > 0 {
		fmt.Fprintf(stderr, "port49d: broker: %d revocation(s) in force from the store that %s lacked; saving them "+
			"to it\n", extra, cfg.Broker.RevocationsFile)
		if err := brk.Persist(ctx); err != nil {
			fmt.Fprintf(stderr, "port49d: broker: saving them: %v; port49_revocations_file_failed is 1\n", err)
		}
	}
	*marks = all
	if err := retry("re-indexing the kept contexts the index lost", func() error {
		// e is the daemon's raw store, outside the guard, as the sweep's is:
		// the scan gets the bulk pool's deadline here.
		uctx, cancel := context.WithTimeout(ctx, cfg.Store.Etcd.BulkTimeout)
		refs, err := e.Unindexed(uctx)
		cancel()
		if err != nil {
			return err
		}
		_, err = brk.ReindexContexts(ctx, refs)
		return err
	}); err != nil {
		return refreshOwed{}, err
	}
	var marked int
	if err := retry("applying the standing revocations to the live contexts", func() (err error) {
		marked, err = brk.ApplyMarksAtStart(ctx, all)
		return err
	}); err != nil {
		return refreshOwed{}, err
	}
	if len(all) > 0 {
		fmt.Fprintf(stderr, "port49d: store: %d standing revocation(s) applied to the live contexts the store kept "+
			"(%d context(s) marked revoked) before serving\n", len(all), marked)
	}
	if err := retry("recording the purge's instant", func() error { return st.SupersedeAll(ctx, brk.Now()) }); err != nil {
		return refreshOwed{}, err
	}
	var n int
	if err := retry("purging the tokens from before this start", func() (err error) {
		n, err = st.PurgeTokens(ctx)
		return err
	}); err != nil {
		return refreshOwed{}, err
	}
	fmt.Fprintf(stderr, "port49d: store: purged %d unspent token(s) from before this start (run 'port49 token' "+
		"again)\n", n)
	var rep broker.RefreshReport
	var owed refreshOwed
	var left error
	if err := retry("carrying the policy in force into the live contexts", func() error {
		var err error
		rep, err = brk.RefreshAtStart(ctx)
		left = err
		owed, err = startLeftBy(err)
		return err
	}, broker.ErrPrincipalUnvisited); err != nil {
		return refreshOwed{}, err
	}
	fmt.Fprintf(stderr, "port49d: store: %d live context(s) carried onto the policy in force (bundle %s) "+
		"before serving\n", rep.Contexts()-rep.Failed, brk.Policy.Load().Bundle)
	if !owed.owed {
		return refreshOwed{}, nil
	}
	when := "again as soon as the listeners are open"
	if !owed.now {
		when = "again at the next retry; every path denies it meanwhile"
	}
	fmt.Fprintf(stderr, "port49d: store: %d live context(s) left unjudged at the start (%v); the listeners open, "+
		"port49_policy_refresh_pending stays 1, and a refresh pass runs %s\n", rep.Failed, left, when)
	return owed, nil
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
			fmt.Fprintf(out, "port49d: store: the index sweep did not finish (%v); it runs again in %v\n", err, every)
		}
		cancel()
		uctx, cancel := context.WithTimeout(ctx, every/2)
		refs, err := s.Unindexed(uctx)
		if err == nil {
			_, err = brk.ReindexContexts(uctx, refs)
		}
		if err != nil && ctx.Err() == nil {
			fmt.Fprintf(out, "port49d: store: finding the contexts the index lost did not finish (%v); it runs again "+
				"in %v\n", err, every)
		}
		cancel()
		ledger.Prune(time.Now())
	}
}

// ledgerPruneEvery is how often pruneLoop prunes the ledger on the memory
// store, which has no sweep.
const ledgerPruneEvery = 10 * time.Minute

// pruneLoop prunes the ledger's marks past their keep every interval
// until ctx ends: sweepLoop's prune, on the memory store.
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
