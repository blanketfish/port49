package port49d

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/inventory"
)

// received is what the fetcher hands the reloader: a document opened, or one
// that did not open (err, with the bytes, so SIGHUP can try them against new
// keys), or the service confirming the etag the fetcher handed over last.
type received struct {
	pub       *inventory.Published
	raw       []byte
	etag      string
	err       error
	unchanged bool
}

// fetcher asks the inventory service every interval (spec §10, "How a daemon
// refreshes its snapshot"): the version first, and the document only when
// its etag is not the last one handed over. It does the network I/O so a
// slow service never holds up a policy reload or a refresh, verifies what
// arrives, and swaps nothing: the reloader is the one goroutine that does.
type fetcher struct {
	client   fetchClient
	keys     func() []ed25519.PublicKey
	url      string
	interval time.Duration
	metrics  *metrics.Metrics
	// etag is the last one handed over; failing the last failure said.
	etag, failing string
}

func (f *fetcher) run(ctx context.Context, out chan<- received, poke <-chan struct{}) {
	tick := time.NewTicker(f.interval)
	defer tick.Stop()
	for {
		if d, ok := f.once(ctx); ok {
			select {
			case out <- d:
			case <-ctx.Done():
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-poke:
			// SIGHUP: fetch the document again, whatever etag is held, so
			// one refused under the old keys is opened under the new.
			f.etag = ""
		}
	}
}

// once asks once. ok is false when there is nothing to hand over: the
// service did not answer, which once says.
func (f *fetcher) once(ctx context.Context) (received, bool) {
	cctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	v, err := f.client.Version(cctx)
	if err == nil && f.etag != "" && v.ETag == f.etag {
		// Counted by the reloader, which alone knows whether the etag
		// confirmed is the document in force or one it refused.
		f.answered()
		return received{etag: v.ETag, unchanged: true}, true
	}
	var raw []byte
	var etag string
	var notModified bool
	if err == nil {
		raw, etag, notModified, err = f.client.Bundle(cctx, f.etag)
	}
	if err != nil {
		if ctx.Err() != nil {
			// port49d is shutting down: nothing failed, and a line saying the
			// service did not answer would be false at 3am (conflict scan F8).
			return received{}, false
		}
		f.metrics.InventoryFetches.WithLabelValues("failed").Inc()
		if msg := oneLine(err); msg != f.failing {
			f.failing = msg
			fmt.Fprintf(stderr, "port49d: inventory: the inventory service at %s did not answer (%s); the bundle "+
				"in force keeps serving, and port49_inventory_snapshot_age_seconds climbs\n", f.url, msg)
		}
		return received{}, false
	}
	f.answered()
	if notModified {
		// Not the header's etag: the one asked with (f.etag), which is what
		// the service said is unchanged. Counted by the reloader.
		return received{etag: f.etag, unchanged: true}, true
	}
	// The etag is port49d's own hash of the bytes, never the header's: it is
	// what the document in force is known by (startDocument), so a service
	// that mislabels a document cannot pass it off as the one confirmed.
	etag = bundle.ETag(raw)
	f.etag = etag
	doc, inv, err := bundle.Open(raw, f.keys())
	if err != nil {
		f.metrics.InventoryFetches.WithLabelValues("invalid").Inc()
		return received{raw: raw, etag: etag, err: err}, true
	}
	f.metrics.InventoryFetches.WithLabelValues("received").Inc()
	return received{pub: &inventory.Published{Raw: raw, Doc: doc, Inv: inv}, raw: raw, etag: etag}, true
}

func (f *fetcher) answered() {
	if f.failing != "" {
		f.failing = ""
		fmt.Fprintf(stderr, "port49d: inventory: the inventory service at %s answers again\n", f.url)
	}
}

// startFetcher starts the fetcher for r in service mode (spec §10): the
// documents it hands over reach r.run through r.docs, a SIGHUP pokes it
// through r.poke, and it opens each document under the verify keys r holds
// now, which SIGHUP may replace. Its first ask is If-None-Match the document
// the start loaded. The channel returned closes once the fetcher has
// returned; port49d waits on it at shutdown, after ctx is done (conflict
// scan F8).
func startFetcher(ctx context.Context, r *reloader, client fetchClient, m *metrics.Metrics) <-chan struct{} {
	docs, poke := make(chan received, 1), make(chan struct{}, 1)
	r.docs, r.poke = docs, poke
	svc := r.cfg.InventoryService
	f := &fetcher{client: client, keys: func() []ed25519.PublicKey { return *r.verifyKeys.Load() },
		url: svc.URL, interval: svc.PollInterval, metrics: m}
	f.etag = r.inForce
	done := make(chan struct{})
	go func() { defer close(done); f.run(ctx, docs, poke) }()
	return done
}
