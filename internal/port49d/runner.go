package port49d

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/crypt"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// runner is one port49-broker's part in the keyspace's one runner (plan
// 7e, Ruling 6): it takes the hold (etcd.Store.Hold, as the broker),
// runs the takeover, then the duties, until the hold is lost or ctx ends;
// then it lets go and tries again every 5s. running is read by the
// reloader's pass to choose the whole refresh or its token half.
type runner struct {
	cfg    config.Config
	brk    *broker.Broker
	raw    *etcdstore.Store // the broker's own, outside the guard: the hold, the sweep, the record
	st     store.Store      // the broker's sealed store
	meta   judgedStore      // meta/judged: raw, but for tests
	ledger *crypt.Ledger
	keys   crypt.Keys
	m      *metrics.Metrics
	alarm  *keyAlarm
	who    string
	held   string // the holder this process last held as, for the waiting line
	rel    *reloader
	// duty is the running duties' context, set once the takeover is done
	// and cleared as they stop: this replica runs while it is set. The
	// pass's context half and meta/judged's writes run under it, so a lost
	// hold ends them with the duties.
	duty atomic.Pointer[context.Context]
	// judge is the policy the latest settled pass left nothing pending
	// under, for the duties to record (settled, judging).
	judge chan *policy.Policy
	// covered is the revision of the ask for a full context pass that the
	// takeover read before its carry, which judged every live context: the
	// duties' watch (owed) owes nothing for it.
	covered uint64
	// copy is this replica's copy of the marks (broker.state_dir/marks.json),
	// and marks the ones it enforces, which its marks feed keeps (Ruling 12).
	copy  *marksCopy
	marks *store.Marks
	// marksReloaded is told, buffered one, when the hook before a marks
	// reload put a mark back: the duties apply the marks to the kept
	// contexts again (restoreMarks).
	marksReloaded chan struct{}
	// witness is this replica's record of the restore witness
	// (broker.state_dir/witness.json; Ruling 18), which the takeover and
	// the duties' keepWitness judge meta/witness against.
	witness *witnessRecord
}

// judgedStore is meta/ as the runner reads and writes it (etcd.Store):
// meta/judged, the replicas' bundles and the ask for a full context pass.
type judgedStore interface {
	Judged(ctx context.Context) (etcdstore.JudgedRecord, bool, error)
	PutJudgedSince(ctx context.Context, bundle string, policy []byte, rev uint64) (bool, error)
	JudgeInDoubt(ctx context.Context, unless string) (bundle string, marked bool, err error)
	BundlesAt(ctx context.Context) ([]etcdstore.BundleRecord, uint64, error)
	RefreshOwed(ctx context.Context) (rev uint64, rec etcdstore.BundleRecord, ok bool, err error)
	ClearRefreshOwed(ctx context.Context, rev uint64) error
}

// errNotRunning is a whole pass asked of a replica that does not run.
var errNotRunning = errors.New("this replica no longer runs the keyspace")

func (r *runner) running() bool { return r.duty.Load() != nil }

// pass is the reloader's refresh pass on port49-broker (Ruling 6): the
// whole Refresh while this replica runs, whose context half is the
// runner's alone, and its token half (RefreshTokens) otherwise. The whole
// Refresh runs under the duties' context too: a lost hold ends it with
// the duties, so no context write lands after another replica may have
// taken over (Task 15 review I-1). A pass cut short so is a stopped one,
// and the reloader's retry is the token half.
func (r *runner) pass(ctx context.Context, priors []broker.Prior) (broker.RefreshReport, error) {
	if r.duty.Load() == nil {
		return r.brk.RefreshTokens(ctx, priors)
	}
	return r.whole(ctx, priors)
}

// whole is the whole Refresh under the duties' context, and errNotRunning
// while this replica does not run: a full context pass a replica owes
// (reloader.full) is never the token half.
func (r *runner) whole(ctx context.Context, priors []broker.Prior) (broker.RefreshReport, error) {
	d := r.duty.Load()
	if d == nil {
		return broker.RefreshReport{}, errNotRunning
	}
	pctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer context.AfterFunc(*d, cancel)()
	return r.brk.Refresh(pctx, priors)
}

// run holds and runs until ctx ends.
func (r *runner) run(ctx context.Context) {
	e := r.cfg.Store.Etcd
	for ctx.Err() == nil {
		lost, release, err := r.raw.Hold(ctx, e.HoldTTL, r.who, func(holder string) {
			if r.held != "" && holder == r.held {
				// This replica's own last run, whose hold was lost and whose
				// lease lives on: never "run by" itself (7d's I-2, 4001732;
				// pre-flight M7).
				fmt.Fprintf(stderr, "port49-broker: runner: keyspace %s is still held by this replica's last run "+
					"(%s); waiting up to hold_ttl (%v) for its lease to expire\n", e.Prefix, lineHolder(holder),
					e.HoldTTL)
				return
			}
			fmt.Fprintf(stderr, "port49-broker: runner: keyspace %s is run by %s; this replica serves the API and "+
				"takes over if that one stops\n", e.Prefix, lineHolder(holder))
		})
		if err != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(stderr, "port49-broker: runner: taking keyspace %s: %v; trying again in 5s\n", e.Prefix, err)
				sleepCtx(ctx, 5*time.Second)
			}
			continue
		}
		r.held = r.who
		r.m.StoreKeyspaceHeld.Set(1)
		fmt.Fprintf(stderr, "port49-broker: runner: took keyspace %s (%s): this replica runs the start, the sweep "+
			"and the policy refresh\n", e.Prefix, lineHolder(r.who))
		dctx, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { defer close(done); r.duties(dctx) }()
		select {
		case <-ctx.Done():
		case <-lost:
			fmt.Fprintln(stderr, "port49-broker: runner: lost the keyspace's hold (its lock key is gone, or etcd "+
				"stopped answering with half its lease or less left); the runner's duties stop; this replica keeps "+
				"serving the API and tries to take the hold again every 5s")
		case <-done:
			// The takeover stopped on an error that waiting does not mend
			// (duties says it): the hold is let go, so another replica may
			// run, and taken again in 5s.
		}
		stop()
		<-done
		r.m.StoreKeyspaceHeld.Set(0)
		// The keeper reports (0, false) as it stops; set them here too, for
		// a takeover that failed before the keeper started (pre-flight I11).
		r.m.LedgerPending.Set(0)
		r.m.LedgerBehind.Set(0)
		release()
		sleepCtx(ctx, 5*time.Second)
	}
}

// duties is the takeover, then the sweep, the ledger record's keeper, the
// restore witness's keeper, meta/judged's writer, the marks' reapplying
// after a put-back and the refresh's context half, until ctx ends.
func (r *runner) duties(ctx context.Context) {
	carried, err := r.takeover(ctx)
	if err != nil {
		if ctx.Err() == nil {
			fmt.Fprintf(stderr, "port49-broker: runner: the takeover stopped: %v; letting the hold go and trying "+
				"again\n", err)
		}
		return
	}
	defer r.duty.Store(nil)
	if !r.begin(ctx, carried) {
		return
	}
	var wg sync.WaitGroup
	wg.Add(6)
	go func() { defer wg.Done(); r.judging(ctx) }()
	go func() { defer wg.Done(); r.keepWitness(ctx) }()
	go func() { defer wg.Done(); r.reapplying(ctx) }()
	go func() { defer wg.Done(); r.owed(ctx) }()
	go func() {
		defer wg.Done()
		sweepLoop(ctx, r.raw, r.brk, r.ledger, r.cfg.Store.Etcd.SweepInterval, stderr)
	}()
	go func() {
		defer wg.Done()
		crypt.KeepLedger(ctx, r.ledger, r.raw, time.Second, func(n int, behind bool) {
			r.m.LedgerPending.Set(float64(n))
			r.m.LedgerBehind.Set(b2f(behind))
		}, func(f string, a ...any) { fmt.Fprintf(stderr, "port49-broker: "+f+"\n", a...) })
	}()
	wg.Wait()
}

// begin starts this replica's run once the takeover carried carried: it
// drops a settled pass an earlier run left unwritten, sets duty, and owes
// a whole pass at once when a policy was swapped in after the carry, whose
// reload ran its first pass as the token half while duty was unset (Task
// 15 review M-6). It reports false when ctx ended first.
func (r *runner) begin(ctx context.Context, carried *policy.Policy) bool {
	select {
	case <-r.judge:
	default:
	}
	r.duty.Store(&ctx)
	if r.brk.Policy.Load() == carried {
		return true
	}
	select {
	case r.rel.owed <- true:
		return true
	case <-ctx.Done():
		return false
	}
}

// settled is the reloader's onSettled: while this replica runs, a pass
// that left nothing pending hands the policy it settled on to the duties
// (judging), keeping only the latest, and never waits: the reloader's
// goroutine is the one that serves SIGHUP and the policy watch (Task 15
// review M-5).
func (r *runner) settled(p *policy.Policy) {
	if !r.running() {
		return
	}
	select {
	case <-r.judge:
	default:
	}
	select {
	case r.judge <- p:
	default:
	}
}

// reapplying, on each marksReloaded, puts back what is still missing
// (restoreMarks) and applies every standing mark the store holds to the
// live contexts, as the takeover does, until ctx ends: a mark the hook put
// back before a marks reload reached this replica's marks and listener
// through the feed, and the contexts the restore put back reach it here.
func (r *runner) reapplying(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.marksReloaded:
		}
		if err := r.restoreMarks(ctx); err != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(stderr, "port49-broker: runner: after a put-back: %v; put back again before the next "+
					"marks reload and at the next takeover\n", err)
			}
			continue
		}
		var all []store.Revocation
		var marked int
		if err := retryCtx(ctx, func() (err error) {
			if all, err = r.st.ListRevocations(ctx); err != nil {
				return fmt.Errorf("listing the revocations in force: %w", err)
			}
			if marked, err = r.brk.ApplyMarksAtStart(ctx, all); err != nil {
				return fmt.Errorf("applying the standing revocations to the live contexts: %w", err)
			}
			return nil
		}); err != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(stderr, "port49-broker: runner: after a put-back: %v; applied again at the next "+
					"takeover\n", err)
			}
			continue
		}
		fmt.Fprintf(stderr, "port49-broker: runner: %d standing revocation(s) applied to the live contexts after a "+
			"put-back (%d context(s) marked revoked)\n", len(all), marked)
	}
}

// putBackMissing puts back, once, every mark this replica's copy holds
// that the store lacks, and returns the ones that landed (plan 7e, Ruling
// 12; pre-flight I5): an etcd restore's lost revocations, or a lift this
// copy missed. Both deny more, and the line says how to lift.
func (r *runner) putBackMissing(ctx context.Context) ([]store.Revocation, error) {
	stored, err := r.st.ListRevocations(ctx)
	if err != nil {
		return nil, err
	}
	missing := r.copy.Missing(stored)
	for i, m := range missing {
		if err := r.st.PutRevocation(ctx, m); err != nil {
			return missing[:i], err
		}
	}
	return missing, nil
}

// restoreMarks is putBackMissing retried while the store is unavailable
// and ctx lives, said either way: the takeover's step, before it applies
// every mark to the kept contexts, and reapplying's on each
// marksReloaded. The marks feed brings what it put back to every process.
func (r *runner) restoreMarks(ctx context.Context) error {
	var put []store.Revocation
	if err := retryCtx(ctx, func() error {
		p, err := r.putBackMissing(ctx)
		put = append(put, p...)
		if err != nil {
			return fmt.Errorf("putting broker.state_dir/marks.json's marks back into the store: %w", err)
		}
		return nil
	}); err != nil {
		if len(put) > 0 {
			sayPutBack(put)
		}
		return err
	}
	if len(put) == 0 {
		fmt.Fprintln(stderr, "port49-broker: runner: every revocation in broker.state_dir/marks.json is in the store")
		return nil
	}
	sayPutBack(put)
	return nil
}

// reloadHook is the marks feed's rescanned on every replica (store.
// FollowMarks; plan 7e, Ruling 12). It counts a rescan. While this replica
// runs, it puts back every mark its copy holds that the store lacks, once
// and bounded, before the reload reads the store: a reload first would
// lift each lost mark from this replica's marks and listener. A put-back
// that fails returns an error, so the reload is refused and the marks
// feed is down until a put-back lands, tried again every second
// (re-review 1 C-2). What it put back is applied to the kept contexts by
// the duties (marksReloaded). A replica that does not run, or runs its
// takeover still, puts nothing back: it keeps in force (store.Marks.Keep)
// every mark it enforces that its copy holds and the store lacks, so its
// listener refuses that principal until the runner's put-back arrives, and
// names them, once for one set (keptSayerAs); a read that fails refuses
// the reload (pre-flight 7e-2 P-3).
func (r *runner) reloadHook(ctx context.Context, rescans prometheus.Counter) func() error {
	say := keptSayerAs(stderr, "port49-broker", "this replica", "as its marks feed reloads", "")
	return func() error {
		rescans.Inc()
		pctx, cancel := context.WithTimeout(ctx, r.cfg.Store.Etcd.BulkTimeout)
		defer cancel()
		if !r.running() {
			stored, err := r.st.ListRevocations(pctx)
			if err != nil {
				return fmt.Errorf("reading the marks before the marks reload: %w; the marks are not reloaded "+
					"until they are read", err)
			}
			var kept []store.Revocation
			for _, m := range r.copy.Missing(stored) {
				if r.marks.Holds(m.Kind, m.Key) {
					r.marks.Keep(m)
					kept = append(kept, m)
				}
			}
			say(kept)
			return nil
		}
		put, err := r.putBackMissing(pctx)
		if len(put) > 0 {
			sayPutBack(put)
			select {
			case r.marksReloaded <- struct{}{}:
			default:
			}
		}
		if err != nil {
			return fmt.Errorf("runner: putting broker.state_dir/marks.json's marks back into the store before the "+
				"marks reload: %w; the marks are not reloaded until they are back", err)
		}
		return nil
	}
}

// sayPutBack is the put-back line, naming each mark (re-check R4).
func sayPutBack(put []store.Revocation) {
	fmt.Fprintf(stderr, "port49-broker: runner: %d revocation(s) in broker.state_dir/marks.json were missing from the "+
		"store (an etcd restore, or a lift made while this replica's watch was compacted away or it was stopped) "+
		"and are put back: %s; lift any that were lifted on purpose with port49 revoke --lift\n", len(put),
		namedMarks(put))
}

// judging records each policy a settled pass hands it as judged, under
// the duties' context, so a lost hold ends the write, until ctx ends.
func (r *runner) judging(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-r.judge:
			r.recordJudged(ctx, p, "a pass left nothing pending")
		}
	}
}

// owed is the runner's watch over the other replicas (plan 7e, Ruling 8
// corrected; pre-flight I3), every policy_watch_interval until ctx ends.
// A replica minting under another bundle makes contexts the runner's
// passes, judged against its own priors, never reach. So:
//   - a replica's ask (meta/refresh_owed), written as it reloads or
//     starts, newer than the last one handled, is a full context pass,
//     cleared at its revision once the pass completes; one that fails stays
//     owed, and the next look asks again;
//   - a replica seen serving another bundle owes one too, once every token
//     it could have minted has expired (owedFullPassAt): a replica that
//     dies unreloaded never asks. It marks meta/judged in doubt at once
//     (doubt), so a takeover meanwhile purges.
func (r *runner) owed(ctx context.Context) {
	every := r.cfg.Policy.WatchInterval
	bound := func(f func(ctx context.Context) error) error {
		bctx, cancel := context.WithTimeout(ctx, every)
		defer cancel()
		return f(bctx)
	}
	handled := r.covered
	if handled != 0 {
		_ = bound(func(c context.Context) error { return r.meta.ClearRefreshOwed(c, handled) })
	}
	var lastMismatch time.Time
	var lastBundle string
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var rev uint64
		var rec etcdstore.BundleRecord
		var ok bool
		err := bound(func(c context.Context) (err error) { rev, rec, ok, err = r.meta.RefreshOwed(c); return })
		if err == nil && ok && rev > handled &&
			r.fullPass(ctx, fullPassOwed{who: lineHolder(rec.Who), bundle: lineBundle(rec.Bundle)}) {
			handled = rev
			_ = bound(func(c context.Context) error { return r.meta.ClearRefreshOwed(c, rev) })
		}
		var recs []etcdstore.BundleRecord
		err = bound(func(c context.Context) (err error) { recs, _, err = r.meta.BundlesAt(c); return })
		now := r.brk.Now()
		if err == nil {
			mine := r.brk.Policy.Load().Bundle
			var other *etcdstore.BundleRecord
			for i, b := range recs {
				// Its own record lags its own swap by a write, and it mints
				// under the policy in force.
				if b.Who != r.who && b.Bundle != mine {
					lastMismatch, lastBundle, other = now, b.Bundle, &recs[i]
				}
			}
			if other != nil {
				_ = bound(func(c context.Context) error { r.doubt(c, *other); return nil })
			}
		}
		if !lastMismatch.IsZero() && !now.Before(owedFullPassAt(lastMismatch)) &&
			r.fullPass(ctx, fullPassOwed{who: "a replica that served another bundle", bundle: lineBundle(lastBundle)}) {
			lastMismatch = time.Time{}
		}
	}
}

// fullPass hands o to the reloader's goroutine, which runs it
// (reloader.full), and reports whether it completed; false too when ctx
// ends first.
func (r *runner) fullPass(ctx context.Context, o fullPassOwed) bool {
	done := make(chan error, 1)
	o.done = done
	select {
	case r.rel.fullPass <- o:
	case <-ctx.Done():
		return false
	}
	select {
	case err := <-done:
		return err == nil
	case <-ctx.Done():
		return false
	}
}

// judgeTries is how many times recordJudged reads the replicas' records
// when one is written between its read and its record.
const judgeTries = 3

// recordJudged writes meta/judged for pol, the policy every live context
// was judged against, retried while the store is unavailable and ctx
// lives, and says so (plan 7e, Ruling 7; pre-flight I2). It is the only
// writer of the record: the takeover calls it once its carry leaves
// nothing owed, and judging whenever a pass leaves nothing pending. It
// writes nothing while any replica's record names another bundle (Ruling
// 8 corrected; pre-flight I3), and marks the record in place in doubt
// (doubt): that replica's tokens, and the contexts they make, carry a
// policy no pass judged, so the next takeover purges, which denies more.
// Nor does it write over a replica's record written after its read
// (PutJudgedSince; Task 15a review I-1): it reads again, judgeTries times
// in all.
func (r *runner) recordJudged(ctx context.Context, pol *policy.Policy, why string) {
	for try := 0; try < judgeTries; try++ {
		var recs []etcdstore.BundleRecord
		var rev uint64
		if err := retryCtx(ctx, func() (err error) { recs, rev, err = r.meta.BundlesAt(ctx); return }); err != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(stderr, "port49-broker: runner: not recording bundle %s as judged: reading the bundles "+
					"the replicas serve: %v; the next takeover purges the unspent tokens\n", pol.Bundle, err)
			}
			return
		}
		for _, b := range recs {
			if b.Bundle != pol.Bundle {
				fmt.Fprintf(stderr, "port49-broker: runner: not recording bundle %s as judged: %s serves bundle %s\n",
					pol.Bundle, lineHolder(b.Who), lineBundle(b.Bundle))
				r.doubt(ctx, b)
				return
			}
		}
		var put bool
		if err := retryCtx(ctx, func() (err error) {
			put, err = r.meta.PutJudgedSince(ctx, pol.Bundle, pol.Raw(), rev)
			return
		}); err != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(stderr, "port49-broker: runner: recording bundle %s as judged: %v; the next takeover "+
					"purges the unspent tokens\n", pol.Bundle, err)
			}
			return
		}
		if put {
			fmt.Fprintf(stderr, "port49-broker: runner: recorded bundle %s as judged (%s)\n", pol.Bundle, why)
			return
		}
	}
	fmt.Fprintf(stderr, "port49-broker: runner: not recording bundle %s as judged: the replicas' records changed at "+
		"each of %d reads; the next takeover purges the unspent tokens\n", pol.Bundle, judgeTries)
}

// doubt withdraws meta/judged while b, another replica's record, names
// another bundle (Task 15a review I-1): the record is marked in doubt, so
// the next takeover purges though the bundle in force is the one it
// names, and says so as it marks. A mark that fails is said; the watch
// (owed) marks again at its next look.
func (r *runner) doubt(ctx context.Context, b etcdstore.BundleRecord) {
	bundle, marked, err := r.meta.JudgeInDoubt(ctx, "")
	if err != nil {
		fmt.Fprintf(stderr, "port49-broker: runner: marking the bundle last judged in doubt (%s serves bundle %s): "+
			"%v; marked again at the next look\n", lineHolder(b.Who), lineBundle(b.Bundle), err)
		return
	}
	if marked {
		fmt.Fprintf(stderr, "port49-broker: runner: the bundle last judged (%s) is in doubt: %s serves bundle %s; the "+
			"next takeover purges the unspent tokens\n", lineBundle(bundle), lineHolder(b.Who), lineBundle(b.Bundle))
	}
}

// witnessEvery is how often the runner reads meta/witness (Ruling 18): the
// ledger keeper's interval, and about the most of a snapshot's lead over
// the last witness that the check cannot see.
const witnessEvery = time.Second

// keepWitness is the runner's half of the restore witness (plan 7e,
// Ruling 18), beside the ledger's keeper, until ctx ends. A pass the
// store does not answer is tried at the next: an outage is the hold's
// fence's to judge.
func (r *runner) keepWitness(ctx context.Context) {
	t := time.NewTicker(witnessEvery)
	defer t.Stop()
	for {
		if err := r.witnessPass(ctx); err != nil && ctx.Err() == nil && !errors.Is(err, store.ErrUnavailable) {
			fmt.Fprintf(stderr, "port49-broker: runner: the restore witness: %v; trying again in %v\n", err,
				witnessEvery)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// witnessPass is one pass of keepWitness. It reads meta/witness first:
// below the replica's record, the store was restored under a running
// runner, and it purges, then has the marks put back (Ruling 12), since a
// watch at a revision the restored store has not reached may not reload.
// Otherwise it rewrites the witness when the read's header is past the
// witness's own revision. A quiet store writes nothing: the rewrite's
// revision is the one the next pass compares with.
func (r *runner) witnessPass(ctx context.Context) error {
	rctx, cancel := context.WithTimeout(ctx, witnessEvery)
	read, gone, why, err := readWitness(rctx, r.witness, r.raw.Witness)
	cancel()
	if err != nil {
		return err
	}
	if gone {
		if err := r.purgeRestored(ctx, why, read); err != nil {
			return err
		}
		select {
		case r.marksReloaded <- struct{}{}:
		default:
		}
		return nil
	}
	if read.Header <= read.ModRevision {
		return nil
	}
	wctx, cancel := context.WithTimeout(ctx, witnessEvery)
	defer cancel()
	landed, err := r.raw.PutWitness(wctx, r.who, read.ModRevision)
	if landed > 0 {
		r.witness.Saw(landed)
	}
	return err
}

// purgeRestored purges every unspent token after the witness caught a
// restore (plan 7e, Ruling 18), as an unjudged takeover does: SupersedeAll
// first, so a replay mints afresh. It lifts no mark: a mark the restore
// lost is the copy's to put back (restoreMarks). It takes the store's
// witness as the replica's record only once the purge is done: until then
// every pass, and every replica's takeover, still sees the restore, so a
// purge cut short by a lost hold is made by the next runner.
func (r *runner) purgeRestored(ctx context.Context, why string, read etcdstore.WitnessRead) error {
	at := r.brk.Now()
	if err := retryCtx(ctx, func() error { return r.st.SupersedeAll(ctx, at) }); err != nil {
		return err
	}
	var n int
	if err := retryCtx(ctx, func() (e error) { n, e = r.st.PurgeTokens(ctx); return }); err != nil {
		return err
	}
	r.witness.Reset(read.ModRevision)
	fmt.Fprintf(stderr, "port49-broker: runner: %s; every unspent token is purged and must be minted again "+
		"(port49 token): %d purged\n", why, n)
	return nil
}

// retryCtx runs f until it returns nil, an error that is not
// store.ErrUnavailable (or one of also), or ctx ends (ctx.Err()), waiting
// 5s between tries and saying each wait. A failure fails toward purging
// at the next takeover, which denies more.
func retryCtx(ctx context.Context, f func() error, also ...error) error {
	for {
		err := f()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		wait := errors.Is(err, store.ErrUnavailable)
		for _, a := range also {
			wait = wait || errors.Is(err, a)
		}
		if !wait {
			return err
		}
		fmt.Fprintf(stderr, "port49-broker: runner: %v; trying again in 5s\n", err)
		if !sleepCtx(ctx, 5*time.Second) {
			return ctx.Err()
		}
	}
}

// sleepCtx waits d or for ctx, and reports whether d passed.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// orNone is bundle, or "none recorded" when !ok.
func orNone(bundle string, ok bool) string {
	if !ok {
		return "none recorded"
	}
	return bundle
}

// refreshOwed is the refresh pass a takeover leaves the reloader: none,
// or one at once (a context still changing; Ruling T12-d) or at the next
// retry (a context under an unheld key; T12-a). Either way
// port49_policy_refresh_pending is 1 until a pass completes.
type refreshOwed struct {
	owed bool
	now  bool
}

// startLeftBy is what the takeover does with what its carry left
// (RefreshAtStart). An outage, or a principal whose contexts could not be
// looked up, holds it: again is that error, which the carry's retry waits
// on, running it again (Ruling T12-c). A context still changing goes on
// owing a pass at once (Ruling T12-d); one under an unheld key goes on
// owing the next retry, since every path denies it meanwhile (Ruling
// T12-a). Any other error is again as well, and ends the takeover.
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

// takeover is what a replica runs on taking the hold, with the API already
// serving (decision 35, a start on etcd; plan 7e, Ruling 6; pre-flight C1,
// M41; re-check IA2):
//  1. records this start's seal keys, warning on the last (checkSealKeys);
//  2. puts back every mark this replica's copy holds that the store lacks
//     (restoreMarks; Ruling 12), then lists the marks, so those are applied
//     with the rest;
//  3. re-indexes every kept context the index lost (raw.Unindexed, then
//     ReindexContexts), so the passes below reach it, and applies every
//     standing mark the store holds to the live contexts it kept, by 7a's
//     two context passes;
//  4. purges the unspent tokens, and supersedes every key, when
//     meta/witness is below this replica's record, the store restored
//     from a snapshot (purgeRestored; Ruling 18), and otherwise only when
//     the bundle in force is not the one meta/judged names (Ruling 7);
//  5. carries the policy in force into every live context the store
//     kept;
//  6. records the bundle as judged when the carry left no pass owed
//     (pre-flight I2), and otherwise tells the reloader the pass owed.
//
// It returns the policy it carried, for begin.
//
// The ledger's base was set before any of it, by runBroker's LoadLedger,
// and the marks were loaded there before the API served. Each step that
// reads the store retries every 5s while it is unavailable, and so does
// step 5 while a principal's contexts cannot be looked up (Ruling T12-c).
func (r *runner) takeover(ctx context.Context) (*policy.Policy, error) {
	e := r.cfg.Store.Etcd
	if err := retryCtx(ctx, func() error {
		return checkSealKeysAs(ctx, "port49-broker", r.raw, r.keys, r.m, stderr, 4*e.CallTimeout, r.alarm, true)
	}); err != nil {
		return nil, err
	}
	// The marks the store lost are put back first, and listed after, so
	// they are applied with the rest (Ruling 12; pre-flight I5).
	if err := r.restoreMarks(ctx); err != nil {
		return nil, err
	}
	var all []store.Revocation
	if err := retryCtx(ctx, func() (err error) {
		if all, err = r.st.ListRevocations(ctx); err != nil {
			return fmt.Errorf("listing the revocations in force: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if err := retryCtx(ctx, func() error {
		// The broker's raw store, outside the guard, as the sweep's is: the
		// scan gets the bulk pool's deadline here.
		uctx, cancel := context.WithTimeout(ctx, e.BulkTimeout)
		refs, err := r.raw.Unindexed(uctx)
		cancel()
		if err == nil {
			_, err = r.brk.ReindexContexts(ctx, refs)
		}
		if err != nil {
			return fmt.Errorf("re-indexing the kept contexts the index lost: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	var marked int
	if err := retryCtx(ctx, func() (err error) {
		if marked, err = r.brk.ApplyMarksAtStart(ctx, all); err != nil {
			return fmt.Errorf("applying the standing revocations to the live contexts: %w", err)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if len(all) > 0 {
		fmt.Fprintf(stderr, "port49-broker: runner: %d standing revocation(s) applied to the live contexts the store "+
			"kept (%d context(s) marked revoked)\n", len(all), marked)
	}
	bundle := r.brk.Policy.Load().Bundle
	var judged etcdstore.JudgedRecord
	var ok bool
	// Retried while unavailable, as every step is: an unavailable read taken
	// as no record would purge when the store's state did not call for it.
	if err := retryCtx(ctx, func() (e error) { judged, ok, e = r.meta.Judged(ctx); return }); err != nil {
		return nil, err
	}
	// The restore witness first (Ruling 18): after an etcd restore,
	// meta/judged is the snapshot's, and names the bundle in force.
	var read etcdstore.WitnessRead
	var gone bool
	var why string
	if err := retryCtx(ctx, func() (e error) {
		read, gone, why, e = readWitness(ctx, r.witness, r.raw.Witness)
		return
	}); err != nil {
		return nil, err
	}
	if !gone && why != "" {
		fmt.Fprintf(stderr, "port49-broker: runner: %s; going by meta/judged alone\n", why)
	}
	switch {
	case gone: // meta/judged is the snapshot's: taken as absent
		if err := r.purgeRestored(ctx, why, read); err != nil {
			return nil, err
		}
	case ok && !judged.InDoubt && judged.Bundle == bundle:
		fmt.Fprintf(stderr, "port49-broker: runner: the bundle in force (%s) is the one the last runner judged; no "+
			"unspent token purged\n", bundle)
	default:
		at := r.brk.Now()
		// SupersedeAll first: a replay after any token is gone mints afresh (Task 5).
		if err := retryCtx(ctx, func() error { return r.st.SupersedeAll(ctx, at) }); err != nil {
			return nil, err
		}
		var n int
		if err := retryCtx(ctx, func() (e error) { n, e = r.st.PurgeTokens(ctx); return }); err != nil {
			return nil, err
		}
		if ok && judged.InDoubt && judged.Bundle == bundle {
			fmt.Fprintf(stderr, "port49-broker: runner: the bundle the last runner judged (%s) is in doubt, a "+
				"replica having served another since; %d unspent token(s) purged (run 'port49 token' again)\n",
				bundle, n)
		} else {
			fmt.Fprintf(stderr, "port49-broker: runner: the bundle in force (%s) is not the one the last runner "+
				"judged (%s); %d unspent token(s) purged (run 'port49 token' again)\n", bundle,
				orNone(judged.Bundle, ok), n)
		}
	}
	// The carry below judges every live context, so an ask for a full
	// context pass written before it is owed nothing more (owed). Read
	// first: an ask written during the carry is newer, and stays owed.
	r.covered = 0
	if err := retryCtx(ctx, func() error {
		rev, _, ok, err := r.meta.RefreshOwed(ctx)
		if ok {
			r.covered = rev
		}
		return err
	}); err != nil {
		return nil, err
	}
	var rep broker.RefreshReport
	var carried *policy.Policy
	var owed refreshOwed
	var left error
	if err := retryCtx(ctx, func() error {
		var err error
		// Loaded before the carry loads it: a swap between the two records
		// the earlier bundle, and the next takeover purges, which denies more.
		carried = r.brk.Policy.Load()
		rep, err = r.brk.RefreshAtStart(ctx)
		left = err
		if owed, err = startLeftBy(err); err != nil {
			return fmt.Errorf("carrying the policy in force into the live contexts: %w", err)
		}
		return nil
	}, broker.ErrPrincipalUnvisited); err != nil {
		return nil, err
	}
	fmt.Fprintf(stderr, "port49-broker: runner: %d live context(s) carried onto the policy in force (bundle %s)\n",
		rep.Contexts()-rep.Failed, carried.Bundle)
	if !owed.owed {
		r.recordJudged(ctx, carried, "the takeover's carry left nothing owed")
		return carried, nil
	}
	when := "again at once"
	if !owed.now {
		when = "again at the next retry; every path denies it meanwhile"
	}
	fmt.Fprintf(stderr, "port49-broker: runner: %d live context(s) left unjudged at the takeover (%v); "+
		"port49_policy_refresh_pending stays 1, and a refresh pass runs %s\n", rep.Failed, left, when)
	// The reloader's own goroutine takes it (reloader.owed): it alone
	// touches the reloader's schedule.
	select {
	case r.rel.owed <- owed.now:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return carried, nil
}
