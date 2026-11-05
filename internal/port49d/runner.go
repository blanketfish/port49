package port49d

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/broker"
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/policy"
	"github.com/blanketfish/port49/internal/printsafe"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/store/crypt"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
	"github.com/blanketfish/port49/internal/store/placement"
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
	// taking is set from the start of the takeover until the duties end:
	// the feeds queue what they bring for the duties from then on (queuing),
	// so a mark or logout that lands after the takeover's snapshot of the
	// marks or the logout set, and before begin, is still reached here.
	taking atomic.Bool
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
	// tookOver is told the policy each takeover carried, once it is done:
	// it opens the start's mint gate (decision 36). nil tells nothing.
	tookOver func(carried *policy.Policy)
	// holdMints closes the mint gate while a purge runs, and opens it again:
	// nil holds nothing.
	holdMints func(on bool)
	// standby is told when another replica runs the keyspace: its takeover
	// is the one that purges, so this replica's start gate need not wait on
	// a purge it owes itself (brokerd.go owes). nil tells nothing.
	standby func()
	// followed is told each mark the marks feed brings that stands, in a
	// split (plan 11a, R20): the duties reach it in this region's session
	// store (reachFollowed). Nil in a shared store, where the broker that
	// made a mark reached it there.
	followed chan store.Revocation
	// followedLogouts is told each logout the logouts feed brings, in a
	// split (R26): the duties reach it in this region's session store.
	followedLogouts chan store.LogoutEntry
	// logoutRescanOwed is set when a logout found followedLogouts full: the
	// duties then reach every entry of logouts, which holds what the queue
	// dropped. wakeLogouts (capacity 1) wakes reachFollowed to do it.
	logoutRescanOwed atomic.Bool
	wakeLogouts      chan struct{}
	// reach reaches a logout here: Broker.ReachLogout, or a test's (nil is
	// the broker's).
	reach func(ctx context.Context, l store.Logout) (broker.RevokeReport, error)
	// dir is the directory store's handle in a split (plan 11a): the
	// hourly key-window recheck reads it (R27). Nil in a shared store.
	dir *dirHandle
	// logouts is the followed copy of the directory's logout records in a
	// split: the takeover reaches every standing one here (R29). Nil in a
	// shared store.
	logouts *store.LogoutSet
	// pending is how many back-channel logouts the last forwarding pass left
	// pending in this region's session store (forwardingPending).
	pending atomic.Int64
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

// queuing is whether the feeds queue what they bring for the duties: from
// the start of the takeover, not only once the duties run. One that the
// takeover also reached is reached twice, which changes nothing.
func (r *runner) queuing() bool { return r.taking.Load() || r.running() }

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
	e := r.cfg.Stores.Session.Etcd
	// The series exists once a runner does, at 0 until the hold is taken.
	r.m.StoreKeyspaceHeld.WithLabelValues().Set(0)
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
			if r.standby != nil {
				r.standby()
			}
		})
		if err != nil {
			if ctx.Err() == nil {
				fmt.Fprintf(stderr, "port49-broker: runner: taking keyspace %s: %v; trying again in 5s\n", e.Prefix, err)
				sleepCtx(ctx, 5*time.Second)
			}
			continue
		}
		r.held = r.who
		r.m.StoreKeyspaceHeld.WithLabelValues().Set(1)
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
		// A purge that failed is still owed (the record says so), but this
		// replica no longer runs it: its mints are not held for a purge the
		// next run makes, which holds them again (purgeRestored).
		if r.holdMints != nil {
			r.holdMints(false)
		}
		r.m.StoreKeyspaceHeld.WithLabelValues().Set(0)
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
// after a put-back, the refresh's context half, the scheduled refresh and
// the directory's pre-warm, until ctx ends.
func (r *runner) duties(ctx context.Context) {
	r.taking.Store(true)
	defer r.taking.Store(false)
	carried, err := r.takeover(ctx)
	if err != nil {
		if ctx.Err() == nil {
			fmt.Fprintf(stderr, "port49-broker: runner: the takeover stopped: %v; letting the hold go and trying "+
				"again\n", err)
		}
		return
	}
	if r.tookOver != nil {
		r.tookOver(carried)
	}
	defer r.duty.Store(nil)
	if !r.begin(ctx, carried) {
		return
	}
	var wg sync.WaitGroup
	wg.Add(8)
	if r.followed != nil {
		wg.Add(2)
		go func() { defer wg.Done(); r.reachFollowed(ctx) }()
		go func() { defer wg.Done(); r.forwardingPending(ctx) }()
	}
	if r.dir != nil {
		wg.Add(2)
		go func() { defer wg.Done(); r.recheckDirectoryKeys(ctx) }()
		go func() { defer wg.Done(); r.putBackLater(ctx) }()
	}
	go func() { defer wg.Done(); r.judging(ctx) }()
	go func() { defer wg.Done(); r.keepWitness(ctx) }()
	go func() { defer wg.Done(); r.reapplying(ctx) }()
	go func() { defer wg.Done(); r.owed(ctx) }()
	go func() {
		defer wg.Done()
		sweepLoop(ctx, r.raw, r.brk, r.ledger, r.cfg.Stores.Session.Etcd.SweepInterval, stderr)
	}()
	go func() {
		defer wg.Done()
		crypt.KeepLedger(ctx, r.ledger, r.raw, time.Second, func(n int, behind bool) {
			r.m.LedgerPending.Set(float64(n))
			r.m.LedgerBehind.Set(b2f(behind))
		}, func(f string, a ...any) { fmt.Fprintf(stderr, "port49-broker: "+f+"\n", a...) })
	}()
	// The scheduled refresh runs with no directory too: it stamps
	// refreshed_at, which session.staleness_ceiling reads. Pre-warm returns
	// at once without one, and its wg.Done runs (pre-flight M-13).
	go func() { defer wg.Done(); r.scheduledDuty(ctx) }()
	go func() { defer wg.Done(); r.prewarmDuty(ctx) }()
	wg.Wait()
}

// scheduledDuty is the scheduled refresh, every broker.refresh_interval,
// under the duties' context.
func (r *runner) scheduledDuty(ctx context.Context) {
	scheduled(ctx, r.brk, r.cfg.Broker.RefreshInterval, runnerSay)
}

// prewarmDuty is the directory's pre-warm; it returns at once without a
// directory, and nothing here reads r.cfg.Broker.Directory.
func (r *runner) prewarmDuty(ctx context.Context) {
	prewarm(ctx, r.brk.Directory, r.brk.Policy, prewarmInterval(r.cfg), runnerSay)
}

func runnerSay(format string, args ...any) {
	fmt.Fprintf(stderr, "port49-broker: "+format+"\n", args...)
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
// copy missed. Both deny more, and the line says how to lift. A lift made
// here between its delete's commit and marksCopy.Lifted can be put back
// too, when the list above falls after the delete and the copy is read
// before Lifted: the same, fail-closed. Each is put with its origin saying
// so (store.PutBackOrigin), so a put-back over a lift's record is said as a
// put-back on every broker, never as a copy a cut held back (task 2 review
// I1).
func (r *runner) putBackMissing(ctx context.Context) ([]store.Revocation, error) {
	stored, err := r.st.ListRevocations(ctx)
	if err != nil {
		return nil, err
	}
	missing := r.copy.Missing(stored)
	for i, m := range missing {
		m.Origin = store.PutBackOrigin(m.Origin)
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
		if len(r.copy.All()) == 0 {
			// Nothing was held, so nothing could be missing: after a restore, the
			// marks made since the snapshot are back only if a broker whose copy
			// holds them runs first (design §13 step 5).
			fmt.Fprintln(stderr, "port49-broker: runner: broker.state_dir/marks.json holds no revocation, so none is put "+
				"back; after a store restore, a revocation made since the snapshot is back only if a broker that "+
				"holds it ran first (design §13 step 5)")
			return nil
		}
		fmt.Fprintln(stderr, "port49-broker: runner: every revocation in broker.state_dir/marks.json is in the store")
		return nil
	}
	sayPutBack(put)
	return nil
}

// putBackLater is the takeover's put-back in a split (R29): restoreMarks,
// which waits for the directory, then the marks applied to the kept
// contexts again when it put any back.
func (r *runner) putBackLater(ctx context.Context) {
	if err := r.restoreMarks(ctx); err != nil {
		return // ctx ended
	}
	select {
	case r.marksReloaded <- struct{}{}:
	default:
	}
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
		pctx, cancel := context.WithTimeout(ctx, r.cfg.Stores.Session.Etcd.BulkTimeout)
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
		"store (an etcd restore, or a lift this replica's watch had not delivered: compacted away, or it stopped first) "+
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
	err := r.witnessPassOnce(ctx)
	if err == nil {
		witnessPassed(r)
	}
	return err
}

// witnessPassed is told each completed pass of a runner's witness; only tests
// swap it, to wait for passes instead of sleeping (keyed by the runner).
var witnessPassed = func(r *runner) {}

func (r *runner) witnessPassOnce(ctx context.Context) error {
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

// purgeRestored purges every unspent token and every once-only record (the
// sign-in challenges, proofs and nonces) after the witness caught a restore,
// or found no record to tell by (plan 7e, Ruling 18; decision 56 ruling 2),
// as an unjudged takeover does: SupersedeAll first, so a replay mints afresh.
// It lifts no mark: a mark the restore lost is the copy's to put back
// (restoreMarks). Mints are held while it runs (holdMints), or a token minted
// in the window would be minted and then deleted. It takes the store's
// witness as the replica's record only once the purge is done and the
// witness has not moved (confirmPurged): until then every pass, and every
// replica's takeover, still owes the purge, and this replica writes no
// meta/witness and saves no witness.json, so a purge cut short is made by
// the next runner.
func (r *runner) purgeRestored(ctx context.Context, why string, read etcdstore.WitnessRead) error {
	// The hold ends with a purge that is done, or with the runner (its ctx):
	// a purge that failed is still owed, and a token minted now would be
	// deleted by the next try.
	done := false
	if r.holdMints != nil {
		r.holdMints(true)
		defer func() {
			if done || ctx.Err() != nil {
				r.holdMints(false)
			}
		}()
	}
	at := r.brk.Now()
	if err := retryCtx(ctx, func() error { return r.st.SupersedeAll(ctx, at) }); err != nil {
		return err
	}
	var n, once int
	if err := retryCtx(ctx, func() (e error) { n, e = r.st.PurgeTokens(ctx); return }); err != nil {
		return err
	}
	if err := retryCtx(ctx, func() (e error) { once, e = r.st.PurgeOnceRecords(ctx); return }); err != nil {
		return err
	}
	took, err := r.confirmPurged(ctx, read.ModRevision)
	if err != nil {
		return err
	}
	done = took
	fmt.Fprintf(stderr, "port49-broker: runner: %s; every unspent token is purged and must be minted again "+
		"(port49 token): %d purged; %d once-only records (sign-in challenges, proofs, nonces) deleted\n", why, n, once)
	return nil
}

// confirmPurged takes the store's witness as the replica's record once a
// purge is done, if meta/witness is still at the ModRevision over (0: absent)
// the purge started from: a witness that has changed means the store may not
// be the one purged, and the record is left, so the next pass judges the
// store again and purges once more. It reports whether it took the record.
func (r *runner) confirmPurged(ctx context.Context, over uint64) (bool, error) {
	var now etcdstore.WitnessRead
	if err := retryCtx(ctx, func() (e error) { now, e = r.raw.Witness(ctx); return }); err != nil {
		return false, fmt.Errorf("confirming the purge against meta/witness: %w", err)
	}
	if now.ModRevision != over {
		fmt.Fprintf(stderr, "port49-broker: runner: meta/witness changed during the purge, so the store may not "+
			"be the one purged; the next pass judges it again\n")
		return false, nil
	}
	r.witness.Reset(over)
	return true, nil
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
// serving and its mints held by the start's gate until a takeover is done
// (decision 35, a start on etcd; plan 7e, Ruling 6; pre-flight C1, M41;
// re-check IA2; decision 36, the mint gate at a start):
//  1. records this start's seal keys, warning on the last (checkSealKeys);
//  2. puts back every mark this replica's copy holds that the store lacks
//     (restoreMarks; Ruling 12), then lists the marks, so those are applied
//     with the rest; in a split it lists the marks it follows instead, and
//     the put-back is its own duty (putBackLater; R29), so a cut holds
//     nothing up;
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
	e := r.cfg.Stores.Session.Etcd
	if err := retryCtx(ctx, func() error {
		return checkSealKeysAs(ctx, "port49-broker", r.raw, r.keys, r.m, stderr, 4*e.CallTimeout, r.alarm, true)
	}); err != nil {
		return nil, err
	}
	var all []store.Revocation
	if r.dir != nil {
		// A split's takeover does not wait for the directory (R29): it applies
		// the marks this process follows, and the put-back is its own duty.
		fmt.Fprintln(stderr, "port49-broker: runner: the put-back of broker.state_dir/marks.json waits for the "+
			"directory store; this region's duties run meanwhile")
		all = r.marks.All()
	} else {
		// The marks the store lost are put back first, and listed after, so
		// they are applied with the rest (Ruling 12; pre-flight I5).
		if err := r.restoreMarks(ctx); err != nil {
			return nil, err
		}
		if err := retryCtx(ctx, func() (err error) {
			if all, err = r.st.ListRevocations(ctx); err != nil {
				return fmt.Errorf("listing the revocations in force: %w", err)
			}
			return nil
		}); err != nil {
			return nil, err
		}
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
	if r.logouts != nil {
		var keys, ctxs, unfinished int
		for _, e := range r.logouts.All() {
			rep, err := r.reachLogout(ctx, e.Logout)
			keys, ctxs = keys+rep.TokenKeys, ctxs+len(rep.Contexts)
			if err != nil && !errors.Is(err, broker.ErrLogoutUnreachable) {
				// Queued (taking is set): the duties reach it again, and say how
				// to end its sessions by hand while it does not finish.
				unfinished++
				r.followLogout(e)
			}
		}
		if n := r.logouts.Len(); n > 0 {
			line := fmt.Sprintf("port49-broker: runner: %d standing logout(s) reached here: %d token key(s), "+
				"%d context(s); %d did not finish", n, keys, ctxs, unfinished)
			if unfinished > 0 {
				line += ", and are tried again once this replica's duties start"
			}
			fmt.Fprintln(stderr, line)
		}
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

// follow is the marks feed's tell in a split, after MarkChanged: a mark
// that stands is queued for the duties to reach here, from the start of the
// takeover (queuing). A replica that does not run queues nothing, and a full
// queue drops the mark,
// said: the marks deny it on every request, and the next takeover
// applies every mark to the live contexts.
func (r *runner) follow(c store.MarkChange) {
	if r.followed == nil || !c.Standing || !r.queuing() {
		return
	}
	select {
	case r.followed <- c.Revocation:
	default:
		fmt.Fprintf(stderr, "port49-broker: runner: a revocation of %s %s was not queued to reach this "+
			"region's tokens (the queue is full); the marks deny it on every request, and the next takeover "+
			"applies it\n", printsafe.Line(c.Key, 160), r.madeBy(c.Revocation))
	}
}

// followLogout queues a logout the feed brought for the running duties,
// as follow queues a mark. A full queue does not drop its reach: the
// logout is in the followed set, so it owes a pass over the whole set
// (logoutRescanOwed), which reachFollowed makes; the counter counts each
// and one line says a run of them.
func (r *runner) followLogout(e store.LogoutEntry) {
	if r.followedLogouts == nil || !r.queuing() {
		return
	}
	select {
	case r.followedLogouts <- e:
	default:
		if r.m != nil {
			r.m.BrokerLogoutsQueueFull.Inc()
		}
		if r.logoutRescanOwed.CompareAndSwap(false, true) {
			fmt.Fprintln(stderr, "port49-broker: runner: the logout queue is full; a pass over the whole logout set "+
				"follows")
		}
		select {
		case r.wakeLogouts <- struct{}{}:
		default:
		}
	}
}

// failedReach is a logout's run of failed reaches: how many in a row, and
// when its record lapses, so a lapsed one is pruned from the count.
type failedReach struct {
	n     int
	until time.Time
}

// reachFailuresSeen, set by a test, is told the failure count's size after
// each logout event; nil in production.
var reachFailuresSeen func(n int)

// reachFollowed reaches each queued mark and logout in this region's session
// store (Broker.ReachMark, Broker.ReachLogout), one line each, until ctx
// ends. A logout whose reach did not finish is queued again after a wait
// (retryLogout), doubling with each failure in a row, while the duties run:
// a logout is enforced on mints and refreshes alone, so only its reach ends
// the person's live contexts here. Every step is safe to run twice. One the
// broker can never reach (ErrLogoutUnreachable) is not tried again; the next
// takeover reaches every standing logout once more.
func (r *runner) reachFollowed(ctx context.Context) {
	failed := map[string]failedReach{}
	// reachOne reaches one logout and says so (a rescan says only its failures,
	// and one line for the pass). It returns false once the duties have ended,
	// and the reach's error.
	reachOne := func(l store.LogoutEntry, quiet bool) (bool, error) {
		now := time.Now()
		for k, f := range failed {
			if !f.until.IsZero() && now.After(f.until) {
				delete(failed, k) // the logout lapsed: nothing is left to reach
			}
		}
		rep, err := r.reachLogout(ctx, l.Logout)
		if err != nil && ctx.Err() != nil {
			return false, err // the duties ended mid-reach: the next takeover reaches it
		}
		line := fmt.Sprintf("port49-broker: runner: a logout made elsewhere (%s) reached %d token key(s) and "+
			"%d context(s) here", printsafe.Line(l.Origin, 160), rep.TokenKeys, len(rep.Contexts))
		switch {
		case err == nil:
			delete(failed, l.Key)
		case errors.Is(err, broker.ErrLogoutUnreachable):
			line += fmt.Sprintf("; not every step finished (%s)", printsafe.Line(err.Error(), 300))
		default:
			f := failed[l.Key]
			f.n++
			f.until = l.Until
			failed[l.Key] = f
			wait := logoutRetryFirst << min(f.n-1, 6)
			if f.n == 1 {
				line += fmt.Sprintf("; not every step finished (%s): it is tried again in %v while this replica "+
					"runs the keyspace, and its mints and refreshes are refused meanwhile; to end its live "+
					"sessions here at once, %s", printsafe.Line(err.Error(), 300), wait,
					r.brk.FollowedLogoutByHand(l.Logout, rep))
			} else {
				line += fmt.Sprintf("; still not reached after %d tries (%s); tried again in %v (the remedy was said with the first failure)", f.n,
					printsafe.Line(err.Error(), 300), wait)
			}
			r.retryLogout(ctx, l, wait)
		}
		if !quiet || err != nil {
			fmt.Fprintln(stderr, line)
		}
		if reachFailuresSeen != nil {
			reachFailuresSeen(len(failed))
		}
		return true, err
	}
	for {
		select {
		case <-ctx.Done():
			return
		case mark := <-r.followed:
			n, refs, err := r.brk.ReachMark(ctx, mark)
			line := fmt.Sprintf("port49-broker: runner: a revocation of %s %s reached %d token "+
				"key(s) and %d context(s) here", printsafe.Line(mark.Key, 160), r.madeBy(mark), n, len(refs))
			if err != nil {
				line += fmt.Sprintf("; not every step finished (%s): the marks deny it on every request, and the "+
					"next takeover applies it again", printsafe.Line(err.Error(), 300))
			}
			fmt.Fprintln(stderr, line)
		case l := <-r.followedLogouts:
			if ok, _ := reachOne(l, false); !ok {
				return
			}
		case <-r.wakeLogouts:
			// A logout found the queue full: reach every entry of the set, which
			// holds what the queue dropped (each reach is safe to run twice).
			if !r.logoutRescanOwed.CompareAndSwap(true, false) || r.logouts == nil {
				continue
			}
			var reached, unfinished, waiting int
			for _, e := range r.logouts.All() {
				if _, retrying := failed[e.Key]; retrying {
					waiting++ // a retry timer already holds it
					continue
				}
				ok, err := reachOne(e, true)
				if !ok {
					return
				}
				if err != nil {
					unfinished++
				} else {
					reached++
				}
			}
			fmt.Fprintf(stderr, "port49-broker: runner: the pass over the whole logout set reached %d logout(s) here; "+
				"%d did not finish (each says why above), and %d already wait to be tried again\n", reached,
				unfinished, waiting)
		}
	}
}

// madeBy says where mark was made, for the runner's lines: "made
// elsewhere", or, when it is this broker's own write that it reported
// unrecorded and that landed late (Marks.FailedWrite), so (post-11b, C2).
func (r *runner) madeBy(mark store.Revocation) string {
	if r.brk != nil && r.brk.Marks.FailedWrite(mark.Kind, mark.Key, mark.At) {
		return "made on this port49-broker, reported unrecorded then,"
	}
	return "made elsewhere"
}

// logoutQueueSize is followedLogouts' capacity.
var logoutQueueSize = 1024

// openLogoutQueue makes the queue followedLogouts and the wake that a full
// one rings, together: a runner with one and not the other would drop a
// logout's reach again, so every runner that follows logouts gets both here.
func (r *runner) openLogoutQueue() {
	r.followedLogouts = make(chan store.LogoutEntry, logoutQueueSize)
	r.wakeLogouts = make(chan struct{}, 1)
}

// logoutRetryFirst is the wait before a failed logout reach is tried again;
// each failure in a row doubles it, up to 64 times it.
var logoutRetryFirst = time.Second

// retryLogout queues l for reachFollowed again after wait, unless the duties
// end first or its record has expired by then.
func (r *runner) retryLogout(ctx context.Context, l store.LogoutEntry, wait time.Duration) {
	go func() {
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !l.Until.IsZero() && time.Now().After(l.Until) {
			return
		}
		select {
		case r.followedLogouts <- l:
		case <-ctx.Done():
		}
	}()
}

// reachLogout is r.reach, else the broker's ReachLogout.
func (r *runner) reachLogout(ctx context.Context, l store.Logout) (broker.RevokeReport, error) {
	if r.reach != nil {
		return r.reach(ctx, l)
	}
	return r.brk.ReachLogout(ctx, l)
}

// forwardingPending forwards this region's pending logouts to the
// directory every 5s while it answers (placement.ForwardPending), sets
// port49_store_logouts_pending, and says each pass that forwarded any, and
// once per run of passes that could not.
func (r *runner) forwardingPending(ctx context.Context) { r.forwardPendingFrom(ctx, r.raw) }

// forwardPendingFrom is forwardingPending over the session store's pending
// records. When the duties end (the hold moved) the gauge and the count are
// zeroed: another replica now reports the pending logouts, and a sum() across
// replicas must not count them twice.
func (r *runner) forwardPendingFrom(ctx context.Context, pending placement.PendingLogouts) {
	defer func() {
		r.m.StoreLogoutsPending.Set(0)
		r.pending.Store(0)
	}()
	said := false
	for {
		n, left, err := placement.ForwardPending(ctx, r.st, pending)
		r.m.StoreLogoutsPending.Set(float64(left))
		r.pending.Store(int64(left))
		switch {
		case n > 0:
			fmt.Fprintf(stderr, "port49-broker: runner: %d pending back-channel logout(s) forwarded to the "+
				"directory store, and so to every region\n", n)
			said = false
		case err != nil && left > 0 && !said:
			fmt.Fprintf(stderr, "port49-broker: runner: %d back-channel logout(s) pending until the directory store "+
				"answers (%s); they are applied in this region already\n", left, printsafe.Line(err.Error(), 300))
			said = true
		}
		if !sleepCtx(ctx, 5*time.Second) {
			return
		}
	}
}
