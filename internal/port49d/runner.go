package port49d

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

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
}

// judgedStore is meta/ as the runner reads and writes it (etcd.Store):
// meta/judged, the replicas' bundles and the ask for a full context pass.
type judgedStore interface {
	Judged(ctx context.Context) (etcdstore.JudgedRecord, bool, error)
	PutJudged(ctx context.Context, bundle string, policy []byte) error
	Bundles(ctx context.Context) ([]etcdstore.BundleRecord, error)
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

// duties is the takeover, then the sweep, the ledger record's keeper,
// meta/judged's writer and the refresh's context half, until ctx ends.
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
	wg.Add(4)
	go func() { defer wg.Done(); r.judging(ctx) }()
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
//     dies unreloaded never asks.
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
		err = bound(func(c context.Context) (err error) { recs, err = r.meta.Bundles(c); return })
		now := r.brk.Now()
		if err == nil {
			mine := r.brk.Policy.Load().Bundle
			for _, b := range recs {
				// Its own record lags its own swap by a write, and it mints
				// under the policy in force.
				if b.Who != r.who && b.Bundle != mine {
					lastMismatch, lastBundle = now, b.Bundle
				}
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

// recordJudged writes meta/judged for pol, the policy every live context
// was judged against, retried while the store is unavailable and ctx
// lives, and says so (plan 7e, Ruling 7; pre-flight I2). It is the only
// writer of the record: the takeover calls it once its carry leaves
// nothing owed, and judging whenever a pass leaves nothing pending. It
// writes nothing while any replica's record names another bundle (Ruling
// 8 corrected; pre-flight I3): that replica's tokens, and the contexts
// they make, carry a policy no pass judged, so the next takeover purges,
// which denies more.
func (r *runner) recordJudged(ctx context.Context, pol *policy.Policy, why string) {
	var recs []etcdstore.BundleRecord
	if err := retryCtx(ctx, func() (err error) { recs, err = r.meta.Bundles(ctx); return }); err != nil {
		if ctx.Err() == nil {
			fmt.Fprintf(stderr, "port49-broker: runner: not recording bundle %s as judged: reading the bundles the "+
				"replicas serve: %v; the next takeover purges the unspent tokens\n", pol.Bundle, err)
		}
		return
	}
	for _, b := range recs {
		if b.Bundle != pol.Bundle {
			fmt.Fprintf(stderr, "port49-broker: runner: not recording bundle %s as judged: %s serves bundle %s\n",
				pol.Bundle, lineHolder(b.Who), lineBundle(b.Bundle))
			return
		}
	}
	if err := retryCtx(ctx, func() error { return r.meta.PutJudged(ctx, pol.Bundle, pol.Raw()) }); err != nil {
		if ctx.Err() == nil {
			fmt.Fprintf(stderr, "port49-broker: runner: recording bundle %s as judged: %v; the next takeover "+
				"purges the unspent tokens\n", pol.Bundle, err)
		}
		return
	}
	fmt.Fprintf(stderr, "port49-broker: runner: recorded bundle %s as judged (%s)\n", pol.Bundle, why)
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
//  2. re-indexes every kept context the index lost (raw.Unindexed, then
//     ReindexContexts), so the passes below reach it;
//  3. applies every standing mark the store holds to the live contexts it
//     kept, by 7a's two context passes;
//  4. purges the unspent tokens, and supersedes every key, only when the
//     bundle in force is not the one meta/judged names (Ruling 7);
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
	if ok && judged.Bundle == bundle {
		fmt.Fprintf(stderr, "port49-broker: runner: the bundle in force (%s) is the one the last runner judged; no "+
			"unspent token purged\n", bundle)
	} else {
		at := r.brk.Now()
		// SupersedeAll first: a replay after any token is gone mints afresh (Task 5).
		if err := retryCtx(ctx, func() error { return r.st.SupersedeAll(ctx, at) }); err != nil {
			return nil, err
		}
		var n int
		if err := retryCtx(ctx, func() (e error) { n, e = r.st.PurgeTokens(ctx); return }); err != nil {
			return nil, err
		}
		fmt.Fprintf(stderr, "port49-broker: runner: the bundle in force (%s) is not the one the last runner judged "+
			"(%s); %d unspent token(s) purged (run 'port49 token' again)\n", bundle, orNone(judged.Bundle, ok), n)
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
