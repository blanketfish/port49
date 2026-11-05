package port49d

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/policy"
	etcdstore "github.com/blanketfish/port49/internal/store/etcd"
)

// restoreSkew is, first, the allowance a restored token's latest expiry may have over
// port49d's clock beyond policy.MaxTokenTTL before the guard stops trusting
// it: a minting broker's clock that far ahead is no clock to wait on. It is
// the largest clock disagreement port49 tolerates anywhere (broker.identity.
// clock_skew's ceiling, an inventory's published_at lead, OCSP and CRL
// ThisUpdate); spec decision 55 ruling 15.
//
// It is also the margin on the scan's MintedAt cutoff (needsScan). MintedAt is
// the minting broker's clock and the cutoff is port49d's, read when it found
// the drop. A restored token was minted before the restore, so before that
// read, but a broker whose clock runs ahead stamps it later than port49d's
// clock then said. The cutoff is therefore the read time plus the skew, never
// less: a restored token is then never missed, and a token a running broker
// mints within the skew after the read is counted too, which can only keep the
// guard longer, never lift it early.
const restoreSkew = 5 * time.Minute

// scanResult is the guard's read of the token family (LatestTokenExpiry),
// taken by pass after a read that needs it: ran is false when none was taken
// or it could not be.
type scanResult struct {
	ran bool
	max time.Time // the largest ExpiresAt among the records, zero when none
	err error
	// cutoff is the MintedAt bound the scan was taken with (needsScan).
	cutoff time.Time
	// unchanged is true when the scan was skipped because the last one was
	// less than scanEvery ago (scanDue): max is then zero and liftAt keeps its
	// value.
	unchanged bool
}

// restoreGuard is port49d's half of the restore witness (plan 7e, Task
// 15d): an etcd restore brings back every single-use token redeemed
// since its snapshot, unspent, and a port49d would redeem it again until
// the first broker runner purges. It keeps the highest meta/witness
// ModRevision it has followed, for the process's life (run): a restore
// that outlasts hold_ttl ends a run, and the next must still know. A read
// that shows the witness below that, or gone after one was seen, guards:
// every token redemption is refused store_unavailable, and nothing else
// is. Two things lift it, the first of: a meta/purged written after the
// read that found the drop (the runner writes one once a purge of every
// unspent token is done, and a plain witness write is no purge), or port49d's
// own clock passing the largest ExpiresAt among the token records, read at
// the drop and again on every guarded read (liftAt, which only rises), judged
// as redemption judges a token's expiry. A scan that fails, a record that does
// not decode, or an expiry further ahead of the clock than a token_ttl and
// restoreSkew arms no bound: only the purge lifts it. After a time lift a
// token expiring at or before liftAt stays refused (floor), so a clock stepped
// back cannot revive a restored one, until a purge. A read that fails changes
// nothing, said once per run of failures. A port49d started after the
// restore has followed nothing and cannot tell: the runbook's token
// delete covers it.
//
// A drop, once judged (all expired, or a bounded guard), re-baselines: later
// reads compare with the witness at the drop (guardHigh), not with the
// pre-restore record, so only a second restore, a witness below that, judges
// again; a restore without --bump-revision, whose witness stays below the old
// record while brokers mint, is not a drop on every pass. The scan counts only
// tokens minted by the cutoff, the drop read's time plus restoreSkew: a token
// a broker minted more than restoreSkew after port49d found the restore never
// arms the guard or extends it. Reads of the same drop scan at most every
// scanEvery while the witness read is unchanged, and the pass that would lift
// scans first and lifts only on a scan that ran. While the witness is below
// the old record after a judged drop, the scan goes on with the drop read's
// own time as the cutoff (no skew: a mint after it is no restored token), so
// a second restore to the old timeline's snapshot is told; a scan that fails
// there guards nothing without a bound: redemptions wait until a scan
// answers, retried on the next read.
type restoreGuard struct {
	out     io.Writer
	mu      sync.Mutex
	high    uint64 // the highest witness followed
	seen    bool
	guarded bool
	// dropAt is the header of the read that found the drop: a meta/purged
	// at or below it may be the snapshot's own.
	dropAt uint64
	// guardHigh is the highest witness read or followed since the drop was
	// judged, guarded or not: a read below it is a second restore.
	guardHigh uint64
	// cutoff is the MintedAt bound of the scans of this drop (needsScan).
	cutoff time.Time
	// lastScan is when the token family was last scanned (scanDue).
	lastScan time.Time
	// lastScanWitness is the witness that read saw: a read of another is not
	// rate-limited (scanDue), because a second restore changes it.
	lastScanWitness uint64
	// scanFailing is true while the scans of a judged drop fail, said once.
	scanFailing bool
	// bounded is true once a scan of the token family succeeded in this
	// guard, and no scan since failed or looked wrong; liftAt, the largest
	// ExpiresAt any scan saw, then says when the guard lifts on its own (zero:
	// no token to wait for). Unbounded, only a purge lifts it, and why says so.
	bounded bool
	liftAt  time.Time
	why     string
	// floor is liftAt at a time lift, or the largest expiry of a scan that
	// found every token expired: a token expiring at or before it stays
	// refused until a purge (RedeemFloor).
	floor time.Time
	// said is true once the line for a drop whose tokens had all expired was
	// said, until the next purge or guard.
	said  bool
	now   func() time.Time
	until prometheus.Gauge
	// checked is false from a run's begin, once a witness was followed,
	// until a read judges the store: the outage that ended the last run
	// may have been the restore.
	checked bool
	failing bool
	gauge   prometheus.Gauge
	ops     *prometheus.CounterVec // port49_store_operations_total; nil counts nothing
}

func newRestoreGuard(out io.Writer) *restoreGuard {
	return &restoreGuard{out: out, checked: true, now: time.Now}
}

// begin starts a run: gauge is its port49_redemption_restore_guarded, set
// at once, until its port49_redemption_restore_guard_until_timestamp_seconds
// (nil sets nothing), ops counts each read as op "restore_read", and redemptions wait
// for the run's first read once a witness was followed.
func (g *restoreGuard) begin(gauge, until prometheus.Gauge, ops *prometheus.CounterVec) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.gauge, g.until, g.ops, g.checked, g.failing = gauge, until, ops, !g.seen, false
	g.setGauge()
}

// RedeemFloor is the expiry at or before which a token stays refused after the
// guard lifted on its own, zero for none: a token minted before the restored
// snapshot ended cannot be redeemed on a clock stepped back, whatever
// port49d's clock says. A purge clears it.
func (g *restoreGuard) RedeemFloor() time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.floor
}

// Allows reports whether a token may be redeemed now.
func (g *restoreGuard) Allows() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.checked && !g.guarded
}

// guardFollowed is told each revision of meta/witness port49d's follower gave
// g, after g took it, and restorePassed each completed pass of g. Only tests
// swap them, to wait on port49d's guard instead of sleeping; both are keyed
// by the guard, not by process, because a test process may run several
// daemons.
var (
	guardFollowed = func(g *restoreGuard, rev uint64) {}
	restorePassed = func(g *restoreGuard) {}
)

// followed is what port49d's FollowWitness calls: Saw, then the hook.
func (g *restoreGuard) followed(rev uint64) {
	g.Saw(rev)
	guardFollowed(g, rev)
}

// Saw raises the witness followed. It never lifts the guard.
func (g *restoreGuard) Saw(rev uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.seen || rev > g.high {
		g.high, g.seen = rev, true
	}
	if g.guarded || g.dropAt != 0 {
		g.guardHigh = max(g.guardHigh, rev)
	}
}

// recorded is the witness followed so far, and the guard's own record
// (guardHigh), taken before a read, as the runner's readWitness takes its
// record: a witness followed while the read is in flight is newer than the
// read, not proof of a drop or of a second restore.
func (g *restoreGuard) recorded() (high uint64, seen bool, guardHigh uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.high, g.seen, g.guardHigh
}

// judge is one read of the store's witness and purge (RestoreRead), or
// its error; high, seen and guardHigh are the record taken before it, and
// sc the scan of the token family if one was needed (needsScan).
func (g *restoreGuard) judge(r etcdstore.RestoreRead, err error, high uint64, seen bool, guardHigh uint64,
	sc scanResult, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ops != nil {
		outcome := "ok"
		if err != nil {
			outcome = "error"
		}
		g.ops.WithLabelValues("restore_read", outcome).Inc()
	}
	if err != nil {
		// A failed read is no restore, but the outage may be one: once a
		// witness was followed, redemptions wait for a read that answers.
		if g.seen {
			g.checked = false
		}
		if !g.failing {
			fmt.Fprintf(g.out, "port49d: store: reading meta/witness, to tell whether the store was restored: %v; "+
				"token redemptions are %s until a read answers; tried again every %v\n", err,
				g.state(), witnessEvery)
		}
		g.failing = true
		return
	}
	g.failing = false
	g.checked = true
	if sc.ran && !sc.unchanged && sc.err == nil {
		g.lastScan, g.lastScanWitness = now, r.Witness
	}
	switch {
	case g.dropAt != 0 && r.Purged > g.dropAt:
		// The runner's purge, after the drop: nothing restored is left.
		said := g.guarded || !g.floor.IsZero()
		g.reset()
		g.high, g.seen = r.Witness, r.Witness > 0
		if said {
			fmt.Fprintln(g.out, "port49d: store: the broker runner's purge after the restore is done; token "+
				"redemptions are served again")
		}
	case g.guarded:
		if r.Witness < guardHigh {
			// A newer restore under the guard: the store now holds that
			// snapshot's tokens, which the re-scan below takes into liftAt
			// (which only rises); a purge must come after this read.
			g.dropAt, g.guardHigh, g.cutoff = r.Header, r.Witness, sc.cutoff
			fmt.Fprintf(g.out, "port49d: store: meta/witness fell to %s while guarded: the store was restored "+
				"again; the guard waits for the tokens it holds now too\n", witnessWords(r.Witness))
		} else {
			g.guardHigh = max(g.guardHigh, r.Witness)
		}
		g.high = max(g.high, r.Witness)
		g.arm(sc, now)
		if g.bounded && !now.Before(g.liftAt) && !sc.unchanged {
			g.expired()
		}
	case g.dropAt != 0:
		// A drop was judged and the guard lifted, or never held: the witness
		// at the drop is the baseline, so only a second restore is a drop.
		g.high = max(g.high, r.Witness)
		switch {
		case r.Witness < guardHigh:
			g.said = false
			g.drop(r, guardHigh, sc, now)
		case sc.ran && !sc.unchanged && sc.err != nil:
			// A failed scan is no judgment here: a guard with no bound on one
			// error would refuse logins until a purge. But it is not proof
			// of none either (a second restore may have brought live
			// tokens): as for a failed read, redemptions wait until a scan
			// answers, and the next pass scans again, rate limit or not.
			g.checked, g.lastScan = false, time.Time{}
			if !g.scanFailing {
				fmt.Fprintf(g.out, "port49d: store: scanning the token records, to tell whether a second restore "+
					"brought tokens back, failed: %v; token redemptions are refused until a scan answers, tried again on the next read\n", sc.err)
			}
			g.scanFailing = true
		case sc.ran && !sc.unchanged && seen && r.Witness < high && sc.max.After(now):
			// Below the record but not below the drop's witness: a second
			// restore, to a snapshot of the old timeline, whose tokens (minted
			// before the first drop's read) are live. A mint after that read
			// is not in the scan, so a running broker's never lands here. The
			// drop's cutoff stays the one of the first.
			g.said, g.scanFailing = false, false
			cutoff := g.cutoff
			g.drop(r, high, sc, now)
			g.cutoff = cutoff
		default:
			if sc.ran && !sc.unchanged {
				g.scanFailing = false
			}
			g.guardHigh = max(g.guardHigh, r.Witness)
		}
	case seen && r.Witness < high:
		g.drop(r, high, sc, now)
	case r.Witness > g.high:
		g.high, g.seen = r.Witness, true
	}
	g.setGauge()
}

func witnessWords(rev uint64) string {
	if rev == 0 {
		return "absent"
	}
	return fmt.Sprintf("at revision %d", rev)
}

// needsScan is whether the read r calls for a scan of the token family
// (LatestTokenExpiry) before it is judged: a guard that is still bounded
// reads it again, to take in any token that appeared (liftAt only rises), and
// a read below the record may be a drop (below the witness at the last drop,
// once one was judged). A purge needs none, and a guard that only a purge lifts
// has none to wait for. record is as judge takes it. cutoff is the MintedAt
// bound of the scan: the time of this read plus restoreSkew for a new drop,
// the drop's own for a guard that is re-reading.
func (g *restoreGuard) needsScan(r etcdstore.RestoreRead, high uint64, seen bool, guardHigh uint64,
	now time.Time) (cutoff time.Time, ok, rescan bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	fresh := now.Add(restoreSkew)
	switch {
	case g.dropAt != 0 && r.Purged > g.dropAt:
		return time.Time{}, false, false
	case g.guarded:
		if g.why != "" {
			return time.Time{}, false, false
		}
		if r.Witness < guardHigh {
			return fresh, true, false
		}
		return g.cutoff, true, true
	case g.dropAt != 0:
		// A judged drop that does not hold. A witness below its own is a second
		// restore. One below the old record, not below that, may be a second
		// restore to a snapshot of the old timeline, whose tokens the first
		// drop's cutoff counts; so the scan goes on, at scanEvery, for as long
		// as the witness stays below the record.
		if r.Witness < guardHigh {
			return fresh, true, false
		}
		// The drop read's own time, with no skew: a mint a broker made after it
		// is no restored token. A restored token a fast broker clock stamps later
		// than the read is left out here, and told only when the witness falls
		// below the drop's.
		return g.cutoff.Add(-restoreSkew), seen && r.Witness < high, true
	}
	return fresh, seen && r.Witness < high, false
}

// scanEvery is the least time between two scans of the token family while a
// drop's cutoff is being re-read. A store-side change counter is no stand-in: a
// ModRevision compares only within one timeline, and a restore brings back keys
// with another's. The pass that would lift the guard always scans first, so a
// token the cheaper passes missed is never lifted over.
const scanEvery = 5 * time.Second

// scanDue is whether a re-read of the same drop scans now: the last scan was
// scanEvery ago (or the clock went back), or the guard's bound is reached and
// this pass would lift it.
func (g *restoreGuard) scanDue(now time.Time, witness uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.lastScan.IsZero() || witness != g.lastScanWitness || now.Before(g.lastScan) || now.Sub(g.lastScan) >= scanEvery ||
		g.guarded && g.bounded && !now.Before(g.liftAt)
}

// reset clears the guard's state, but not the record of the witness; g.mu is
// held.
func (g *restoreGuard) reset() {
	g.guarded, g.bounded, g.liftAt, g.why, g.floor, g.said, g.dropAt, g.guardHigh, g.cutoff, g.lastScan, g.scanFailing =
		false, false, time.Time{}, "", time.Time{}, false, 0, 0, time.Time{}, time.Time{}, false
}

// arm takes a scan into the guard's bound: liftAt only rises. A scan that was
// not taken or failed, a record that did not decode, or a latest expiry
// further ahead of port49d's clock than a token_ttl and restoreSkew leave
// only the purge to lift the guard, for as long as it lasts. It says nothing
// of a record. g.mu is held.
func (g *restoreGuard) arm(sc scanResult, now time.Time) {
	if g.why != "" {
		return
	}
	switch {
	case !sc.ran || sc.err != nil && !errors.Is(sc.err, etcdstore.ErrTokenRecord):
		g.why = "the token records could not be read"
	case sc.err != nil:
		g.why = "a token record does not decode"
	case sc.max.After(now.Add(policy.MaxTokenTTL + restoreSkew)):
		g.why = fmt.Sprintf("the latest token expiry %s is more than %v ahead of this port49d's clock",
			sc.max.UTC().Format(time.RFC3339), policy.MaxTokenTTL+restoreSkew)
	}
	if g.why != "" {
		g.bounded, g.liftAt = false, time.Time{}
		return
	}
	g.bounded = true
	g.liftAt = laterOf(g.liftAt, sc.max)
}

func laterOf(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// expired lifts the guard once port49d's clock passed liftAt, the largest
// expiry of every token it saw: nothing restored is redeemable now. A token
// expiring at or before liftAt stays refused (floor) until a purge. The record
// of the witness is not taken, so a later restore is still told. g.mu is held.
func (g *restoreGuard) expired() {
	last := g.liftAt
	g.floor = laterOf(g.floor, last)
	g.guarded, g.bounded, g.liftAt, g.why = false, false, time.Time{}, ""
	if last.IsZero() {
		fmt.Fprintln(g.out, "port49d: store: the token records hold no token; token redemptions are served again")
		return
	}
	fmt.Fprintf(g.out, "port49d: store: every token the restored snapshot held has now expired (the latest, at %s, "+
		"on this port49d's clock); token redemptions are served again. A token expiring at or before that stays "+
		"refused until a broker runner's purge, so a clock stepped back redeems nothing restored\n",
		last.UTC().Format(time.RFC3339))
}

// drop is a read that found the witness below followed: a restore, or a read
// below the record after a lift. A scan that shows every token expired guards
// nothing: the floor keeps them refused, and the line is said once. Any other
// guards, until a purge or until the latest expiry has passed. g.mu is held.
func (g *restoreGuard) drop(r etcdstore.RestoreRead, followed uint64, sc scanResult, now time.Time) {
	at := witnessWords(r.Witness)
	g.dropAt, g.guardHigh, g.cutoff = r.Header, r.Witness, sc.cutoff
	if sc.ran && sc.err == nil && !sc.max.After(now) {
		g.floor = laterOf(g.floor, sc.max)
		if !g.said {
			g.said = true
			held := "its token records hold none"
			if !sc.max.IsZero() {
				held = "the latest, at " + sc.max.UTC().Format(time.RFC3339) + ", has expired"
			}
			fmt.Fprintf(g.out, "port49d: store: meta/witness is %s, below the %d this port49d followed: the store was "+
				"restored from a snapshot, and no token in it is redeemable (%s); token redemptions are served. A broker "+
				"runner still purges; follow the restore runbook (design §13) for the marks and revocations the "+
				"snapshot lost\n", at, followed, held)
		}
		return
	}
	g.guarded, g.said = true, false
	g.bounded, g.liftAt, g.why = false, time.Time{}, ""
	g.arm(sc, now)
	until := "until a broker runner's purge is done (" + g.why + ", so only the purge lifts it)"
	if g.bounded {
		until = "until a broker runner's purge is done or, at the latest, " + g.liftAt.UTC().Format(time.RFC3339) +
			", when every token the snapshot holds has expired (the largest expiry among its token records, on this " +
			"port49d's clock; a token minted meanwhile moves it later)"
	}
	fmt.Fprintf(g.out, "port49d: store: meta/witness is %s, below the %d this port49d followed: the store was "+
		"restored from a snapshot, which brings back every token redeemed since it, unspent; every token "+
		"redemption is refused (store_unavailable) %s, and a device whose "+
		"authentication ERROR is final (IOS-XE) refuses break-glass too: start the brokers; a runner's purge "+
		"line releases this port49d. If no runner says one (its purge landed before this port49d's first "+
		"read, or meta/judged survived the restore and no witness record was kept), delete the restored "+
		"tokens as etcd's root (etcdctl del --prefix <prefix>v1/t/) and then restart this port49d, or stop every "+
		"port49-broker, delete meta/judged and start them, so a takeover purges; never restart this port49d before "+
		"the restored tokens are deleted: it forgets the drop and redeems them. Follow the restore runbook's "+
		"step 3 (design §13) before another restore\n", at, followed, until)
}

func (g *restoreGuard) state() string {
	if g.guarded || !g.checked {
		return "refused"
	}
	return "served"
}

// setGauge sets the run's gauges: 1 while guarded, not while a run waits
// for its first read or a failed read; and the time the guard lifts on its
// own (liftAt), 0 while it does not hold or only a purge lifts it. g.mu is held.
func (g *restoreGuard) setGauge() {
	if g.gauge != nil {
		g.gauge.Set(b2f(g.guarded))
	}
	if g.until != nil {
		if g.guarded && g.bounded {
			g.until.Set(float64(g.liftAt.Unix()))
		} else {
			g.until.Set(0)
		}
	}
}

// keep follows meta/witness and reads it, with meta/purged, at once and
// every witnessEvery, each read given the store's own deadline, the longer
// of witnessEvery and callTimeout, until ctx ends: the watch alone can wait at a
// revision a store restored without --bump-revision has not reached, and
// never tell.
func (g *restoreGuard) keep(ctx context.Context, s *etcdstore.Store, callTimeout time.Duration) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); s.FollowWitness(ctx, g.followed) }()
	defer wg.Wait()
	t := time.NewTicker(witnessEvery)
	defer t.Stop()
	for {
		if !g.pass(ctx, callTimeout, s.RestoreRead, s.LatestTokenExpiry) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// pass is one read and its judgment: the record is taken before the read
// (recorded), so a witness followed while it is in flight is no drop. It
// reports false once ctx ended, with nothing judged.
func (g *restoreGuard) pass(ctx context.Context, callTimeout time.Duration,
	read func(context.Context) (etcdstore.RestoreRead, error),
	scan func(context.Context, time.Time) (time.Time, error)) bool {
	high, seen, guardHigh := g.recorded()
	rctx, cancel := context.WithTimeout(ctx, max(witnessEvery, callTimeout))
	r, err := read(rctx)
	cancel()
	if ctx.Err() != nil {
		return false
	}
	var sc scanResult
	now := g.now() // once per pass: the scan decision and the judgment share it
	if err == nil && scan != nil {
		if cutoff, ok, rescan := g.needsScan(r, high, seen, guardHigh, now); ok {
			if rescan && !g.scanDue(now, r.Witness) {
				sc = scanResult{ran: true, cutoff: cutoff, unchanged: true}
			} else {
				sctx, scancel := context.WithTimeout(ctx, max(witnessEvery, callTimeout))
				latest, serr := scan(sctx, cutoff)
				scancel()
				if ctx.Err() != nil {
					return false
				}
				sc = scanResult{ran: true, max: latest, err: serr, cutoff: cutoff}
			}
		}
	}
	g.judge(r, err, high, seen, guardHigh, sc, now)
	restorePassed(g)
	return true
}
