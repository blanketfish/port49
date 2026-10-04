package port49d

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/printsafe"
	"github.com/rhwendt/port49/internal/store"
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

// startRecorder is what a replica's start records through (etcd.Store):
// its bundle's record and, when that is not the bundle last judged, the
// mark on meta/judged.
type startRecorder interface {
	PutBundle(ctx context.Context, who, bundle string, ttl time.Duration) error
	JudgeInDoubt(ctx context.Context, unless string) (bundle string, marked bool, err error)
}

// recordStart is recordAtStart, swapped in tests to hold a start there.
var recordStart = recordAtStart

// recordAtStart is what a replica records before it serves anything that
// mints: its first bundle record (firstBundle; Task 15a review M-1), then,
// when meta/judged names another bundle, the record marked in doubt
// (flagSkew; re-review 1, I-2), so a replica that stops before the
// runner's watch looks still has the next takeover purge. The record lands
// first: a runner's PutJudgedSince that read the records before it is
// refused, and one that read them after it declines.
func recordAtStart(ctx context.Context, st startRecorder, who, bundle string, ttl, call, wait time.Duration,
	out io.Writer) error {
	if err := firstBundle(ctx, st, who, bundle, ttl, call, wait, out); err != nil {
		return err
	}
	return untilLanded(ctx, fmt.Sprintf("marking the bundle last judged in doubt against this replica's (%s)",
		bundle), call, wait, out, func(ctx context.Context) error { return flagSkew(ctx, st, bundle, out) })
}

// firstBundle records the bundle this replica serves before it serves
// anything that mints (Task 15a review M-1): the runner judges meta/judged
// against the replicas' records, so a replica it cannot see mints nothing.
func firstBundle(ctx context.Context, raw startRecorder, who, bundle string, ttl, call, wait time.Duration,
	out io.Writer) error {
	return untilLanded(ctx, fmt.Sprintf("recording the bundle this replica serves (%s)", bundle), call, wait, out,
		func(ctx context.Context) error { return raw.PutBundle(ctx, who, bundle, ttl) })
}

// untilLanded runs f, each try bounded by call, until it lands or ctx
// ends: one the store did not answer, or that is one of also, is tried
// again every wait, each distinct error said once as what. Any other
// error ends it.
func untilLanded(ctx context.Context, what string, call, wait time.Duration, out io.Writer,
	f func(ctx context.Context) error, also ...error) error {
	said := ""
	for {
		pctx, cancel := context.WithTimeout(ctx, call)
		err := f(pctx)
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		retry := errors.Is(err, store.ErrUnavailable)
		for _, a := range also {
			retry = retry || errors.Is(err, a)
		}
		if !retry {
			return fmt.Errorf("%s: %w", what, err)
		}
		if line := fmt.Sprintf("port49-broker: policy: %s: %v; nothing that mints is served until it lands, "+
			"trying again every %s", what, err, wait); line != said {
			fmt.Fprintln(out, line)
			said = line
		}
		if !sleepCtx(ctx, wait) {
			return ctx.Err()
		}
	}
}

// skewMarker is flagSkew's shape.
type skewMarker func(ctx context.Context, st startRecorder, bundle string, out io.Writer) error

// markSkew is flagSkew, swapped in tests to hold a swap's mark: while the
// replica runs, so atomically.
var markSkew atomic.Pointer[skewMarker]

func init() {
	f := skewMarker(flagSkew)
	markSkew.Store(&f)
}

// flagSkew marks meta/judged in doubt unless it names bundle, the one this
// replica serves (re-review 1, I-2), and says so when this call marked it.
// The mark is the replica's own: the runner's watch samples the replicas'
// records, and skew that comes and goes between two looks is never seen.
func flagSkew(ctx context.Context, st startRecorder, bundle string, out io.Writer) error {
	judged, marked, err := st.JudgeInDoubt(ctx, bundle)
	if err != nil {
		return err
	}
	if marked {
		fmt.Fprintf(out, "port49-broker: policy: this replica serves bundle %s and the bundle last judged is %s: "+
			"marked it in doubt, so the next takeover purges the unspent tokens\n", bundle, lineBundle(judged))
	}
	return nil
}

// skewGate is a replica's mint gate (broker.Broker.MintGate; Task 15a
// re-review 1, I-2): a mint runs only under the bundle this replica last
// flagged against meta/judged (flagSkew), so a replica that cannot mark
// the bundle last judged in doubt mints nothing under its own. The start
// flags its bundle before anything that mints is served, and the asker
// flags each swap's once its mark lands, the runner's included
// (re-review 2, I-3).
type skewGate struct{ flagged atomic.Pointer[string] }

func (g *skewGate) flag(bundle string) { g.flagged.Store(&bundle) }

func (g *skewGate) allow(pol *policy.Policy) error {
	if f := g.flagged.Load(); f != nil && *f == pol.Bundle {
		return nil
	}
	return fmt.Errorf("bundle %s is not yet flagged against the bundle last judged", pol.Bundle)
}

// flagSwap is the asker's half of every swap to bundle, the runner's too
// (re-review 1, I-2; re-review 2, I-3): it marks meta/judged in doubt when
// it names another bundle (markSkew), and only then opens gate to mints
// under bundle. A mark the store did not answer, or refused (a role
// edited, then fixed), is tried again every wait until it lands or ctx
// ends (re-review 2, M-8): a replica that cannot flag its skew mints
// nothing under it (broker.Broker.MintGate). closed, the gauge
// port49_broker_mint_gate_closed, reads 1 while it waits (re-review 3,
// I-4); readiness never shows it, a store fault being an alarm (design
// §12).
func flagSwap(ctx context.Context, st startRecorder, gate *skewGate, bundle string, call, wait time.Duration,
	closed prometheus.Gauge, out io.Writer) {
	closed.Set(1)
	if untilLanded(ctx, fmt.Sprintf("marking the bundle last judged in doubt against this replica's (%s)",
		bundle), call, wait, out, func(ctx context.Context) error { return (*markSkew.Load())(ctx, st, bundle, out) },
		store.ErrRefused) == nil {
		gate.flag(bundle)
		closed.Set(0)
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

// judgedBundleReader reads meta/judged_bundle (etcd.Store): the name of the
// bundle last judged, which is all port49d's role may read of meta/judged.
type judgedBundleReader interface {
	JudgedBundle(ctx context.Context) (bundle string, ok bool, err error)
}

// keepDaemonBundle is port49d's half (re-check R5): its own policy file
// decides admission, quarantine and redaction, and can differ from the
// brokers'. Its role cannot write meta/, so it records nothing; it reads
// the bundle the runner last judged (meta/judged_bundle) every every, gauges
// whether its own is that one, and says a mismatch once per pair. Right
// after a rollout the record lags until the runner's settle pass, so a 0
// then is expected for that long. With no record nothing is known to
// differ: it gauges 1 and says nothing. A store that does not answer
// leaves the gauge as it was.
func keepDaemonBundle(ctx context.Context, judged judgedBundleReader, live *policy.Live, every time.Duration,
	m *metrics.Metrics, out io.Writer) {
	t := time.NewTicker(every)
	defer t.Stop()
	said := ""
	for {
		mine := live.Load().Bundle
		rctx, cancel := context.WithTimeout(ctx, every)
		theirs, ok, err := judged.JudgedBundle(rctx)
		cancel()
		if err == nil {
			match := !ok || theirs == mine
			m.PolicyBundleMatchesRunner.Set(b2f(match))
			if pair := mine + " " + theirs; !match && pair != said {
				fmt.Fprintf(out, "port49d: policy: this port49d serves bundle %s and the bundle last judged by "+
					"the runner is %s; set the same policy file on port49d (policy.file) as on every port49-broker "+
					"(broker.policy_file)\n", mine, lineBundle(theirs))
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
