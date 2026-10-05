package crypt

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// LoadLedger seeds l at a start (plan 7e, Rulings 3, 4): every mark the
// ledger record holds (src; nil reads none), then every live context at one
// revision, each opened with keys to read its sequence. A scanned record
// below its key's recorded mark is a put-back and raises nothing; one that
// will not open is skipped, since a read of it is unreadable anyway. It
// sets the base just past the scan's revision and returns that revision,
// how many keys l knows, and how many came from the record.
//
// A ledger loaded before (a re-entry after a store gone keeps it) is
// seeded and scanned as the feed is followed: a record or a recorded mark
// at a key it has no mark for makes one only at or above the base it had,
// so a put-back made while the store was away is not taken as its key's
// (pre-flight I1). Only then is the base raised.
//
// It attaches l's fence at the scan's revision: from here every fenced
// read waits for FollowContexts to deliver past it, so the caller starts
// it at once.
func LoadLedger(ctx context.Context, feed store.ContextFeed, src store.LedgerSource, keys Keys,
	l *Ledger) (rev uint64, known, recorded int, err error) {
	first := l.Base() == 0
	if recorded, err = seedFrom(ctx, src, l); err != nil {
		return 0, 0, 0, err
	}
	rev, err = feed.ScanContexts(ctx, func(k store.ContextKey, c store.Context) { observe(l, keys, k, c, first) })
	if err != nil {
		return 0, 0, 0, err
	}
	l.SetBase(rev + 1)
	l.Fence().Attach(rev)
	return rev, l.Len(), recorded, nil
}

// observe raises k's mark from c, sealed, if it opens: making a mark for
// any record at a first start's scan, and as ObserveFollowed otherwise.
// The plaintext revoked_at goes with it, so a revocation another process
// could not seal is this one's floor once the feed or the scan brings it,
// at the mark or below it (revokedBelow).
func observe(l *Ledger, keys Keys, k store.ContextKey, c store.Context, first bool) {
	oc, seq, err := openContextWith(keys, k, c)
	if err != nil {
		return
	}
	if first {
		l.Observe(k, seq, c.Rev, c.RevokedAt, oc.SessionExpires)
		l.floorBelow(k, c.Rev, c.RevokedAt)
		return
	}
	l.ObserveFollowed(k, seq, c.Rev, c.RevokedAt, oc.SessionExpires)
}

// seedFrom raises l from every mark the ledger record holds (src; nil reads
// none), and returns how many it read. On a ledger never loaded (base 0)
// each makes its key's mark; on one loaded, each is followed as a scanned
// record is (seedFollowed), so a recorded mark below the base makes no
// entry the base would have denied.
func seedFrom(ctx context.Context, src store.LedgerSource, l *Ledger) (int, error) {
	if src == nil {
		return 0, nil
	}
	_, ms, err := src.LedgerMarks(ctx)
	if err != nil {
		return 0, fmt.Errorf("reading the ledger record: %w", err)
	}
	first := l.Base() == 0
	for _, m := range ms {
		if first {
			l.Seed(m)
		} else {
			l.seedFollowed(m)
		}
	}
	return len(ms), nil
}

// rescan is a compacted watch's catch-up (re-check R1): the ledger
// record's marks first, as a start seeds them, then every live context,
// raising only. A scan sees each key's latest record, not the writes in
// between: a later login a put-back hid while the watch was down is in
// the record, when the runner's feed saw it, and nowhere in the scan.
func rescan(ctx context.Context, feed store.ContextFeed, src store.LedgerSource, keys Keys,
	l *Ledger) (uint64, error) {
	if _, err := seedFrom(ctx, src, l); err != nil {
		return 0, err
	}
	return feed.ScanContexts(ctx, func(k store.ContextKey, c store.Context) { observe(l, keys, k, c, false) })
}

// FollowContexts keeps l current from feed after `from` until ctx ends,
// and returns ctx's error then (plan 7e, Ruling 3). Each change raises its
// key's mark and never lowers one; a delete changes nothing. A compacted
// watch seeds from src and scans again (rescan), raising only, tells
// rescanned, and goes on from the later of the scan's revision and the
// last change delivered; a rescan that fails is a watch that failed. A
// watch that fails is tried again every second, from the last revision
// the watch delivered through: its last change or its last progress
// notification, so a quiet family's re-watch resumes above a compaction
// (final review 7e-1 I-1). up is told whether the watch is running
// (port49_store_feed_up{feed="contexts"}), and logf says each rescan,
// each failure once per run of them, and the first change or progress
// delivered after a run of them.
//
// It moves l's fence (Fenced): each revision the watch has delivered
// through, and each rescan's revision once its marks are in; a waiting
// read's ask goes to the watch as a progress request, and is made again
// for each new watch while the read still waits.
//
// A change the feed brings again, after a re-watch or a rescan, is below
// or at the mark it raised: Observe never lowers a mark, and takes a
// plaintext revoked_at as the floor only from a record at the mark, or
// through the sequences below the revocation's own revision
// (revokedBelow), so nothing brought again lowers a mark or revokes a
// record written after it.
func FollowContexts(ctx context.Context, feed store.ContextFeed, src store.LedgerSource, keys Keys,
	l *Ledger, from uint64, up func(bool), rescanned func(), logf func(string, ...any)) error {
	failing := false
	// again is the first change or progress a watch delivers after a stop:
	// the feed follows the store again, and says so (final review 7e-1
	// I-2).
	again := func() {
		if failing {
			logf("store: the context feed follows the store again")
			failing = false
		}
	}
	for {
		up(true)
		l.Fence().SetUp(true)
		l.Fence().askAgain()
		err := feed.WatchContexts(ctx, from, func(c store.ContextChange) {
			again()
			if c.Rev > from {
				from = c.Rev
			}
			if !c.Deleted {
				observe(l, keys, c.Key, c.Context, false)
			}
		}, func(rev uint64) {
			again()
			from = max(from, rev)
			l.Fence().Followed(rev)
		}, l.Fence().Asks())
		l.Fence().SetUp(false)
		up(false)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, store.ErrCompacted) {
			logf("store: the context feed's revision was compacted; seeding from the ledger record and scanning " +
				"the store again")
			rescanned()
			if rev, serr := rescan(ctx, feed, src, keys, l); serr == nil {
				l.Fence().Followed(rev) // only once the seed and the scan are in
				from = max(from, rev)
				continue
			} else {
				err = serr
			}
		}
		if !failing {
			logf("store: the context feed stopped (%v); trying again every second", err)
			failing = true
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// KeepLedger writes l's raised marks to sink every `every` until ctx ends
// (plan 7e, Ruling 4): the keyspace's holder alone runs it. A write that
// fails is said once per run of failures, and the marks it did not land
// are owed again; those it landed are not, so a record too large for one
// round's budget still progresses. report is told after each round how
// many marks are owed (port49_ledger_pending), and whether the context
// feed is down (port49_ledger_behind): then the ledger is not raised by
// other processes' logins, and pending cannot show what the record misses.
// When ctx ends it writes what is still owed once, within keeperStopFlush,
// so a graceful stop leaves its last round in the record, says what that
// write could not land, and reports (0, false) once, so a runner whose
// duties stopped shows no stale value (pre-flight I11).
func KeepLedger(ctx context.Context, l *Ledger, sink store.LedgerSink, every time.Duration,
	report func(pending int, behind bool), logf func(string, ...any)) {
	t := time.NewTicker(every)
	defer t.Stop()
	defer report(0, false)
	// write writes what is owed within timeout, owes again what did not
	// land, and returns how many that is and why.
	write := func(ctx context.Context, timeout time.Duration) (int, error) {
		ms := l.Dirty()
		if len(ms) == 0 {
			return 0, nil
		}
		wctx, cancel := context.WithTimeout(ctx, timeout)
		n, err := sink.PutLedgerMarks(wctx, ms)
		cancel()
		if err == nil {
			return 0, nil
		}
		l.Redirty(ms[min(max(n, 0), len(ms)):])
		return len(ms) - min(max(n, 0), len(ms)), err
	}
	failing := false
	for {
		select {
		case <-ctx.Done():
			if owed, err := write(context.WithoutCancel(ctx), keeperStopFlush); err != nil {
				logf("store: stopping with %d ledger mark(s) not written to the ledger record (%v); a context "+
					"put back at those keys before the next start would be taken", owed, err)
			}
			return
		case <-t.C:
		}
		owed, err := write(ctx, 10*every+5*time.Second)
		switch {
		case err != nil && !failing:
			logf("store: writing the ledger record failed (%v); %d mark(s) owed, tried again every %v; a "+
				"context put back at those keys would be taken after a restart", err, owed, every)
			failing = true
		case err == nil && failing:
			logf("store: the ledger record is written again")
			failing = false
		}
		report(l.Pending(), !l.Fence().Up())
	}
}

// keeperStopFlush bounds a stopping keeper's last write: a stop with the
// store down waits this long, no longer.
const keeperStopFlush = 2 * time.Second
