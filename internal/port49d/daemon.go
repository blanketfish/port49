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
// through the reload (store.Marks.Keep), until a lift this feed delivers
// or a restart, and named on out. A lift made on a broker while the feed
// was down is kept too: that denies more, and the runner's copy puts back
// what the restore lost. A read that fails refuses the reload (re-review 1
// C-2). Each call counts a rescan.
func daemonReloadHook(ctx context.Context, feed store.MarkFeed, enforced *store.Marks,
	rescans prometheus.Counter, bound time.Duration, out io.Writer) func() error {
	return func() error {
		rescans.Inc()
		return keepLost(ctx, feed, enforced, bound, "as its marks feed reloads", out)
	}
}

// keepLost keeps in force every mark enforced holds that the store lacks,
// and names them on out; when says at which load. The reload hook runs it,
// and so does a run after a store gone before its LoadMarks: the marks are
// the process's (Ruling 11), and an etcd restore that outlasts hold_ttl
// ends the run before the feed can reload (pre-flight 7e-2 P-1). A read
// that fails returns an error, and the caller loads nothing.
func keepLost(ctx context.Context, feed store.MarkFeed, enforced *store.Marks, bound time.Duration,
	when string, out io.Writer) error {
	rctx, cancel := context.WithTimeout(ctx, bound)
	_, rs, err := feed.Revocations(rctx)
	cancel()
	if err != nil {
		return fmt.Errorf("reading the marks before the marks reload: %w; the marks are not reloaded "+
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
	if len(kept) > 0 {
		fmt.Fprintf(out, "port49d: store: %d revocation(s) this port49d enforces are missing from the store "+
			"%s (an etcd restore, or lifted on port49-broker while the feed was down) and stay in force "+
			"here until a lift this feed delivers or a restart: %s\n", len(kept), when, namedMarks(kept))
	}
	return nil
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
