package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/fence"
	"github.com/rhwendt/port49/internal/inventory"
)

// fetchClient is what port49d asks the inventory service: the version, and
// the document. *inventory.Client is one.
type fetchClient interface {
	Version(ctx context.Context) (inventory.VersionInfo, error)
	Bundle(ctx context.Context, etag string) ([]byte, string, bool, error)
}

// persistedName is the copy port49d keeps in inventory.service.state_dir.
const persistedName = "bundle.json"

// readPersisted is port49d's own copy (spec §10: "the last good bundle is
// persisted to local disk"), read behind the write fence, since whoever can
// write it decides a restart's inventory, and verified. nil, nil when there
// is none.
func readPersisted(dir string, keys []ed25519.PublicKey) (*inventory.Published, error) {
	path := filepath.Join(dir, persistedName)
	raw, err := fence.Read(path, bundle.MaxDocument, "persisted bundle")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	doc, inv, err := bundle.Open(raw, keys)
	if err != nil {
		return nil, inventory.NotOpened(path, err)
	}
	return &inventory.Published{Raw: raw, Doc: doc, Inv: inv}, nil
}

// readMirrorFile is the shared mirror's copy (spec §10). The mount is the
// deployment's and anyone with the store's credentials may write it, so the
// signature, not the file's owner, is what is checked. nil, nil with no
// mirror or no copy in it.
func readMirrorFile(dir string, keys []ed25519.PublicKey) (*inventory.Published, error) {
	if dir == "" {
		return nil, nil
	}
	p, err := inventory.OpenSignedFile(filepath.Join(dir, persistedName), keys)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return p, err
}

// readMirror is the mirror read, swapped in tests; mirrorDeadline bounds it.
var (
	readMirror     = readMirrorFile
	mirrorDeadline = 10 * time.Second
)

// requestTimeout bounds one ask of the service: one that accepts and never
// answers must not stretch the retries (pre-flight minor 5).
const requestTimeout = 30 * time.Second

// errMirrorHung is a mirror read that did not return by mirrorDeadline: no
// document was read, so none was refused.
var errMirrorHung = errors.New("mirror read timed out")

// mirrorWithin reads the mirror under mirrorDeadline (pre-flight M4). A
// read from a FUSE, NFS or object-store CSI mount that has hung blocks in
// the kernel, and O_NONBLOCK does not help on a regular file, so the read
// runs in a goroutine that is abandoned at the deadline: a hung mount costs
// the start ten seconds and one goroutine, never the start itself (spec §10:
// a restart in place needs nothing). A shutdown does not wait for it either.
func mirrorWithin(ctx context.Context, dir string, keys []ed25519.PublicKey) (*inventory.Published, error) {
	type result struct {
		p   *inventory.Published
		err error
	}
	done := make(chan result, 1)
	read := readMirror // read before the goroutine: a test swaps the variable back while it blocks
	go func() {
		p, err := read(dir, keys)
		done <- result{p, err}
	}()
	timer := time.NewTimer(mirrorDeadline)
	defer timer.Stop()
	select {
	case r := <-done:
		return r.p, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-timer.C:
		return nil, fmt.Errorf("mirror_dir %s did not answer in %s: %w", dir, mirrorDeadline, errMirrorHung)
	}
}

// persistBundle keeps raw as port49d's copy: atomic, 0600, in a directory
// only port49d's user can write.
func persistBundle(dir string, raw []byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return inventory.WriteAtomic(dir, persistedName, raw, 0o600)
}

// maxPublishedSkew is how far in the future a document's published_at may
// be, for clock skew between the service and port49d. A document published
// later than that is refused: it would beat every genuinely later copy at a
// cold start, and date the snapshot in the future.
const maxPublishedSkew = 5 * time.Minute

// publishedInFuture refuses p when its published_at is more than
// maxPublishedSkew after now.
func publishedInFuture(p *inventory.Published, now time.Time) error {
	if p.Doc.PublishedAt.After(now.Add(maxPublishedSkew)) {
		return fmt.Errorf("bundle %d is published %s, more than %s after this host's clock (%s); check the "+
			"inventory service's clock", p.Doc.Sequence, p.Doc.PublishedAt.Format(time.RFC3339), maxPublishedSkew,
			now.UTC().Format(time.RFC3339))
	}
	return nil
}

// coldStart is port49d's first inventory with inventory.service (spec §10,
// "Cold start"; Decided 5): the newer of its persisted copy and the mirror's,
// and with neither, the service, asked every poll_interval until it answers.
// Only that last case waits, and while it does port49d serves no TACACS+ and
// /readyz answers 503 with why (rd), since the caller has not opened the
// listener. Each reason it is still waiting is said once.
//
// Newer is the later published_at. A tie keeps the persisted copy: it is
// port49d's own, already on disk, so nothing is rewritten.
//
// port49_inventory_bundle_refused is 1 when a document was read and failed
// verification or the checks — bundle.Open, or a published_at too far in the
// future — whichever source it came from; the service confirming the bundle
// in force, or sending another, clears it (a start from the service is that
// confirmation). A copy that could not be read at all — absent, unreadable,
// refused by the fence, the wrong shape, or a mirror that hung — is said, with
// why, and not counted as refused: no document was judged. A mirror that
// could not be read sets port49_inventory_mirror_unreadable instead.
//
// Every copy is opened against keys before any field of it is read. The
// document's own bundle ID is never printed or trusted: the one in force is
// the one port49d computes from its policy and the document's inventory.
func coldStart(ctx context.Context, svc *config.InventoryServiceConfig, keys []ed25519.PublicKey,
	c fetchClient, m *metrics.Metrics, rd *readiness) (*inventory.Published, string, error) {
	persistedWhy, mirrorWhy := "none in "+svc.StateDir, "none configured"
	// judge is what a copy in dir that was read is held to beyond
	// bundle.Open.
	judge := func(dir string, p *inventory.Published, err error) (*inventory.Published, error) {
		if err == nil && p != nil {
			if ferr := publishedInFuture(p, time.Now()); ferr != nil {
				return nil, inventory.NotOpened(filepath.Join(dir, persistedName), ferr)
			}
		}
		return p, err
	}
	var best *inventory.Published
	from := ""
	p, err := readPersisted(svc.StateDir, keys)
	if p, err = judge(svc.StateDir, p, err); err != nil {
		persistedWhy = oneLine(err)
		if errors.Is(err, inventory.ErrNotOpened) {
			m.InventoryBundleRefused.Set(1) // refused, said once, and alarmed (spec §10)
			fmt.Fprintf(stderr, "port49d: inventory: the persisted copy is refused: %s\n", persistedWhy)
		} else {
			fmt.Fprintf(stderr, "port49d: inventory: the persisted copy is passed over: %s\n", persistedWhy)
		}
	} else if p != nil {
		best, from = p, "the persisted copy"
	}
	if svc.MirrorDir != "" {
		mirrorWhy = "none in " + svc.MirrorDir
		mc, err := mirrorWithin(ctx, svc.MirrorDir, keys)
		mc, err = judge(svc.MirrorDir, mc, err)
		switch {
		case ctx.Err() != nil:
			return nil, "", ctx.Err()
		case errors.Is(err, inventory.ErrNotOpened):
			mirrorWhy = oneLine(err)
			m.InventoryBundleRefused.Set(1)
			fmt.Fprintf(stderr, "port49d: inventory: the mirror's copy is refused: %s\n", mirrorWhy)
		case err != nil:
			mirrorWhy = oneLine(err)
			m.InventoryMirrorUnreadable.Set(1)
			fmt.Fprintf(stderr, "port49d: inventory: the mirror's copy is passed over: %s\n", mirrorWhy)
		case mc != nil && (best == nil || mc.Doc.PublishedAt.After(best.Doc.PublishedAt)):
			// Newer is later publication: a sequence starts again at 1
			// after a service reset, a publication time does not
			// (pre-flight minor 11).
			if best != nil {
				fmt.Fprintf(stderr, "port49d: inventory: the mirror's bundle %d, published %s, is published later "+
					"than the persisted copy's bundle %d, published %s\n", mc.Doc.Sequence,
					mc.Doc.PublishedAt.Format(time.RFC3339), best.Doc.Sequence, best.Doc.PublishedAt.Format(time.RFC3339))
			}
			best, from = mc, "the mirror's copy"
		}
	}
	said := ""
	for best == nil {
		rd.waiting()
		rctx, cancel := context.WithTimeout(ctx, requestTimeout)
		raw, _, _, err := c.Bundle(rctx, "")
		cancel()
		if err == nil {
			doc, inv, oerr := bundle.Open(raw, keys)
			p := &inventory.Published{Raw: raw, Doc: doc, Inv: inv}
			if oerr == nil {
				oerr = publishedInFuture(p, time.Now())
			}
			if oerr == nil {
				best, from = p, "the service"
				break
			}
			m.InventoryBundleRefused.Set(1)
			err = fmt.Errorf("its bundle is refused: %w", oerr)
		}
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		if why := fmt.Sprintf("port49d: inventory: no bundle yet (persisted copy: %s; mirror: %s; service at %s: %s); "+
			"TACACS+ is not served until one arrives, and /readyz answers 503 (spec §10, cold start)", persistedWhy,
			mirrorWhy, svc.URL, oneLine(err)); why != said {
			fmt.Fprintln(stderr, why)
			said = why
		}
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-time.After(svc.PollInterval):
		}
	}
	if from == "the service" {
		// The service sent the document now in force: whatever copy was
		// refused on the way is behind it.
		m.InventoryBundleRefused.Set(0)
	}
	if from != "the persisted copy" {
		if err := persistBundle(svc.StateDir, best.Raw); err != nil {
			m.InventoryPersistFailed.Set(1)
			fmt.Fprintf(stderr, "port49d: inventory: state_dir %s: %s; a restart with the service down will "+
				"need the mirror\n", svc.StateDir, oneLine(err))
		}
	}
	fmt.Fprintf(stderr, "port49d: inventory: starting from bundle %d (%s), published %s; the service at %s is "+
		"asked every %s\n", best.Doc.Sequence, from, best.Doc.PublishedAt.Format(time.RFC3339), svc.URL,
		svc.PollInterval)
	return best, from, nil
}
