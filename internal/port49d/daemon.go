package port49d

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
)

// probe pings the store through the daemon's guard every every until ctx
// ends (plan 7e, Ruling 11). With no hold, nothing else asks the store while
// no device does, so a hung store would go unnoticed until the first
// packet, which a device would hear as store_unavailable rather than as a
// closed port. Each ping counts toward the context pool's circuit, which,
// open for hold_ttl, ends the run as a store gone (guard.Config.StopAfter),
// as 7d's fence did. Plan 7f replaces it with go-dark proper.
func probe(ctx context.Context, s store.RevStore, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, every)
			s.Ping(pctx) // its outcome is the guard's to count
			cancel()
		}
	}
}

// daemonReloadHook is port49d's rescanned for its marks feed on etcd with
// no broker inside (store.FollowMarks; plan 7e, Ruling 5). The daemon's
// role cannot write rv/, and broker.revocations_file is retired on etcd
// (Ruling 12), so a mark an etcd restore lost cannot be put back here as
// 7e-1's marksReloadHook put it back (final review 7e-1 C-1). Instead
// every mark this port49d enforces that the store lacks is kept in force
// through the reload (store.Marks.Keep), until it is revoked again and
// lifted on port49-broker, or a restart, and named on out, once for one
// set (keptSayer). A lift
// made on a broker while the feed was down is kept too: that denies more,
// and the runner's copy puts back what the restore lost. A read that
// fails refuses the reload (re-review 1 C-2). Each call counts a rescan.
func daemonReloadHook(ctx context.Context, feed store.MarkFeed, enforced *store.Marks,
	rescans prometheus.Counter, bound time.Duration, out io.Writer) func() error {
	return keepingReloadHook(ctx, feed, enforced, rescans, bound, keptSayer(out, "as its marks feed reloads"))
}

// keepingReloadHook is a marks feed's rescanned that puts nothing back:
// each call counts a rescan, keeps in force every mark enforced holds that
// the store lacks (keepLost), and tells say which; a read that fails
// refuses the reload: port49d's (daemonReloadHook). port49-broker's is
// the runner's (runner.reloadHook), whose copy puts back what the store
// lost (plan 7e, Ruling 12).
func keepingReloadHook(ctx context.Context, feed store.MarkFeed, enforced *store.Marks,
	rescans prometheus.Counter, bound time.Duration, say func([]store.Revocation)) func() error {
	return func() error {
		rescans.Inc()
		kept, err := keepLost(ctx, feed, enforced, bound)
		if err != nil {
			return err
		}
		say(kept)
		return nil
	}
}

// loadDaemonMarks is one attempt at a run's marks load on etcd with no
// broker inside: after a store gone (again), keepLost first, then
// LoadMarks, so each attempt the start retries keeps what the store lost
// before it loads, as FollowMarks runs its hook before every load (task
// 14 review M-3). It returns the revision the load read at.
func loadDaemonMarks(ctx context.Context, feed store.MarkFeed, enforced *store.Marks, again bool,
	bound time.Duration, say func([]store.Revocation)) (uint64, error) {
	if again {
		kept, err := keepLost(ctx, feed, enforced, bound)
		if err != nil {
			return 0, fmt.Errorf("store: %w", err)
		}
		say(kept)
	}
	lctx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	rev, err := store.LoadMarks(lctx, feed, enforced, nil)
	if err != nil {
		return 0, fmt.Errorf("store: reading the revocations in force: %w", err)
	}
	return rev, nil
}

// keepLost keeps in force every mark enforced holds that the store lacks,
// and returns them. The reload hook runs it, and so does a run after a
// store gone before its LoadMarks: the marks are the process's (Ruling
// 11), and an etcd restore that outlasts hold_ttl ends the run before the
// feed can reload (pre-flight 7e-2 P-1). A read that fails returns an
// error, and the caller loads nothing.
func keepLost(ctx context.Context, feed store.MarkFeed, enforced *store.Marks,
	bound time.Duration) ([]store.Revocation, error) {
	rctx, cancel := context.WithTimeout(ctx, bound)
	_, rs, err := feed.Revocations(rctx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("reading the marks before the marks reload: %w; the marks are not reloaded "+
			"until they are read", err)
	}
	stored := map[[2]string]bool{}
	for _, r := range rs {
		stored[[2]string{r.Kind, r.Key}] = true
	}
	var kept []store.Revocation
	for _, r := range enforced.All() {
		if !stored[[2]string{r.Kind, r.Key}] {
			enforced.Keep(r)
			kept = append(kept, r)
		}
	}
	return kept, nil
}

// keptSayer names on out the marks keepLost kept, when says at which
// load, once for one set: a store that flaps reloads the feed every
// second, and the line, naming up to 20 marks, would repeat with it (task
// 14 review M-1). A set that changes is said, and so is one after a call
// that kept nothing. The remedy it names works: a lift alone of a mark the
// store lacks lifts nothing on port49-broker (broker.ErrNotRevoked) and
// reaches no feed, but a revoke puts the mark in the store, which the
// feed delivers, and a lift after it is delivered as a lift (task 14
// review I-2).
func keptSayer(out io.Writer, when string) func([]store.Revocation) {
	return keptSayerAs(out, "port49d", "this port49d", when, ", or restart this port49d")
}

// keptSayerAs is keptSayer for proc, the process its lines begin with,
// which self names: port49d's "this port49d", a port49-broker's "this
// replica", whose line names the same release (task 14 review I-2), and
// also after it: port49d's restart, which a port49-broker's lacks, since
// its copy keeps the mark through a restart too (keepCopied).
func keptSayerAs(out io.Writer, proc, self, when, also string) func([]store.Revocation) {
	said := ""
	return func(kept []store.Revocation) {
		var set strings.Builder
		for _, r := range kept {
			set.WriteString(r.Kind + "\x00" + r.Key + "\x00")
		}
		if set.String() == said {
			return
		}
		said = set.String()
		if len(kept) > 0 {
			fmt.Fprintf(out, "%s: store: %d revocation(s) %s enforces are missing from the store "+
				"%s (an etcd restore, or lifted on port49-broker while the feed was down) and stay in force "+
				"here (to release one lifted on purpose, revoke it again on port49-broker, then lift it with "+
				"port49 revoke --lift%s): %s\n", proc, len(kept), self, when, also, namedMarks(kept))
		}
	}
}

// namedMarks names each mark a put-back or keep line lists, its kind and
// key, printed safe, at most 20, then how many more (re-check R4): the
// operator lifts again what was lifted on purpose, and port49 revoke
// --list shows the rest.
func namedMarks(ms []store.Revocation) string {
	const most = 20
	var names []string
	for i, m := range ms {
		if i == most {
			names = append(names, fmt.Sprintf("and %d more", len(ms)-most))
			break
		}
		names = append(names, m.Kind+" "+printsafe.Line(m.Key, 256))
	}
	return strings.Join(names, ", ")
}
