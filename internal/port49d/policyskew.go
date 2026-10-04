package port49d

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/printsafe"
	etcdstore "github.com/rhwendt/port49/internal/store/etcd"
)

// bundleStore is what keepBundle reads and writes (etcd.Store).
type bundleStore interface {
	PutBundle(ctx context.Context, who, bundle string, ttl time.Duration) error
	DeleteBundle(ctx context.Context, who string) error
	Bundles(ctx context.Context) ([]etcdstore.BundleRecord, error)
	Holder(ctx context.Context) (string, bool, error)
}

// keepBundle records the bundle this replica serves, leased for ttl and
// renewed every third of it and at every swap, and gauges whether it is
// the runner's (plan 7e, Ruling 8; pre-flight I3): each replica reads its
// own broker.policy_file, and propagation can skew them past any settle
// window. A mismatch is said once per pair of bundles. A store that does
// not answer leaves the gauge as it was: the record lapses on its own.
func keepBundle(ctx context.Context, raw bundleStore, who string, live *policy.Live, ttl time.Duration,
	swapped <-chan struct{}, m *metrics.Metrics, out io.Writer) {
	t := time.NewTicker(ttl / 3)
	defer t.Stop()
	said := ""
	for {
		mine := live.Load().Bundle
		rctx, cancel := context.WithTimeout(ctx, ttl/3)
		_ = raw.PutBundle(rctx, who, mine, ttl)
		recs, err := raw.Bundles(rctx)
		holder, held, herr := raw.Holder(rctx)
		cancel()
		if err == nil && herr == nil && held {
			theirs, match := mine, true
			for _, r := range recs {
				if r.Who == holder {
					theirs, match = r.Bundle, r.Bundle == mine
				}
			}
			m.PolicyBundleMatchesRunner.Set(b2f(match))
			if pair := mine + " " + theirs; !match && pair != said {
				fmt.Fprintf(out, "port49-broker: policy: this replica serves bundle %s and the runner (%s) serves "+
					"bundle %s; set the same broker.policy_file content and broker.policy_watch_interval on every "+
					"replica\n", mine, lineHolder(holder), lineBundle(theirs))
				said = pair
			} else if match {
				said = ""
			}
		}
		select {
		case <-ctx.Done():
			// A replica that stops mints nothing more: its record goes with it,
			// so a takeover right after a rollout judges the replicas that serve.
			// One that dies leaves its record to lapse (ExpiresAt).
			dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			_ = raw.DeleteBundle(dctx, who)
			cancel()
			return
		case <-t.C:
		case <-swapped:
		}
	}
}

// lineBundle is a bundle a store record names, as a line may echo it:
// whoever can write meta/ writes it (lineHolder).
func lineBundle(b string) string { return printsafe.Line(b, 100) }

// owedFullPassAt is when the runner owes a full context pass after it last
// saw a replica serve another bundle: every token that replica could have
// minted under it has expired by then, so the pass reaches every context
// one of them made (pre-flight I3).
func owedFullPassAt(lastMismatch time.Time) time.Time { return lastMismatch.Add(policy.MaxTokenTTL) }

// keepDaemonBundle is port49d's half (re-check R5): its own policy file
// decides admission, quarantine and redaction, and can differ from the
// brokers'. Its role cannot write meta/, so it records nothing; it reads
// the bundle the runner last judged (meta/judged) every every, gauges
// whether its own is that one, and says a mismatch once per pair. Right
// after a rollout the record lags until the runner's settle pass, so a 0
// then is expected for that long. With no record nothing is known to
// differ: it gauges 1 and says nothing. A store that does not answer
// leaves the gauge as it was.
func keepDaemonBundle(ctx context.Context, judged judgedReader, live *policy.Live, every time.Duration,
	m *metrics.Metrics, out io.Writer) {
	t := time.NewTicker(every)
	defer t.Stop()
	said := ""
	for {
		mine := live.Load().Bundle
		rctx, cancel := context.WithTimeout(ctx, every)
		rec, ok, err := judged.Judged(rctx)
		cancel()
		if err == nil {
			match := !ok || rec.Bundle == mine
			m.PolicyBundleMatchesRunner.Set(b2f(match))
			if pair := mine + " " + rec.Bundle; !match && pair != said {
				fmt.Fprintf(out, "port49d: policy: this port49d serves bundle %s and the bundle last judged by "+
					"the runner is %s; set the same policy file on port49d (policy.file) as on every port49-broker "+
					"(broker.policy_file)\n", mine, lineBundle(rec.Bundle))
				said = pair
			} else if match {
				said = ""
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
