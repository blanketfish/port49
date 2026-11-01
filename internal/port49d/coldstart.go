package port49d

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/blanketfish/port49/internal/bundle"
	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/fence"
	"github.com/blanketfish/port49/internal/inventory"
	"github.com/blanketfish/port49/internal/policy"
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

// coldNow is cold start's clock, swapped in tests.
var coldNow = time.Now

// publishedAhead is a document refused only for its published_at being more
// than maxPublishedSkew after this host's clock. Either clock may be the
// wrong one, so a copy refused for it alone is judged again at every pass of
// the wait: a host that booted behind and is put right by NTP starts from
// its copy then, with the service still down (spec §10: a restart in place
// needs nothing).
type publishedAhead struct{ msg string }

func (e *publishedAhead) Error() string { return e.msg }

// publishedInFuture refuses p when its published_at is more than
// maxPublishedSkew after now.
func publishedInFuture(p *inventory.Published, now time.Time) error {
	if p.Doc.PublishedAt.After(now.Add(maxPublishedSkew)) {
		return &publishedAhead{fmt.Sprintf("bundle %d is published %s, more than %s after this host's clock (%s); "+
			"this host's clock or the signer's is wrong", p.Doc.Sequence, p.Doc.PublishedAt.Format(time.RFC3339),
			maxPublishedSkew, now.UTC().Format(time.RFC3339))}
	}
	return nil
}

// coldCopy is one of the two copies a cold start reads: which, and how.
type coldCopy struct {
	name string // "the persisted copy", "the mirror's copy"
	dir  string
	read func() (*inventory.Published, error)
}

// coldPick is a copy cold start could start from, and where it came from.
type coldPick struct {
	p    *inventory.Published
	from string // "the persisted copy", "the mirror's copy", "the service"
}

// coldCopies is port49d's first inventory with inventory.service (spec §10,
// "Cold start"; Decided 5): its persisted copy and the mirror's, newer
// first — the start's choice, then what it falls back to when the policy
// refuses that (startCopy) — and with neither, the service, asked every
// poll_interval until it answers. Only that last case waits, and while it
// does port49d serves no TACACS+ and /readyz answers 503 with why (rd), since
// the caller has not opened the listener. Each reason it is still waiting is
// said once. It persists nothing: a copy is kept only once the policy and
// the broker have accepted it (persistStart; final review I2).
//
// Newer is the later published_at. A tie keeps the persisted copy: it is
// port49d's own, already on disk, so nothing is rewritten.
//
// port49_inventory_bundle_refused is 1 when a document was read and failed
// verification or the checks — bundle.Open, or a published_at too far in the
// future — whichever source it came from; the service confirming the bundle
// in force, or sending another, clears it (a start from the service is that
// confirmation), as does a start from a copy when every refusal was only of
// a published_at this host's clock had not reached. A copy that could not be
// read at all — absent, unreadable, refused by the fence, the wrong shape, or
// a mirror that hung — is said, with why, and not counted as refused: no
// document was judged. A mirror that could not be read sets
// port49_inventory_mirror_unreadable instead.
//
// A copy refused only for being published ahead of this clock is read and
// judged again, whole, at each pass of the wait (publishedAhead).
//
// Every copy is opened against keys before any field of it is read. The
// document's own bundle ID is never printed or trusted: the one in force is
// the one port49d computes from its policy and the document's inventory.
func coldCopies(ctx context.Context, proc string, svc *config.InventoryServiceConfig, keys []ed25519.PublicKey,
	c fetchClient, m *metrics.Metrics, rd *readiness) ([]coldPick, error) {
	// Each line begins with proc, the process's name (procOf).
	say := func(format string, args ...any) { fmt.Fprintf(stderr, proc+": "+format, args...) }
	copies := []coldCopy{{name: "the persisted copy", dir: svc.StateDir,
		read: func() (*inventory.Published, error) { return readPersisted(svc.StateDir, keys) }}}
	if svc.MirrorDir != "" {
		copies = append(copies, coldCopy{name: "the mirror's copy", dir: svc.MirrorDir,
			read: func() (*inventory.Published, error) { return mirrorWithin(ctx, svc.MirrorDir, keys) }})
	}
	why := map[string]string{"the persisted copy": "none in " + svc.StateDir, "the mirror's copy": "none configured"}
	if svc.MirrorDir != "" {
		why["the mirror's copy"] = "none in " + svc.MirrorDir
	}
	// ahead holds the copies refused only for their published_at; refusedOther
	// is set once any document is refused for anything else, which only the
	// service's word clears.
	var ahead []coldCopy
	refusedOther := false
	// judge reads cp, opens it, and holds it to the clock reading now; a
	// copy it cannot use is said, with why, and alarmed if a document was
	// read. again is a copy judged again for the clock, whose still being
	// ahead was said.
	judge := func(cp coldCopy, again bool, now time.Time) *inventory.Published {
		p, err := cp.read()
		if err == nil && p != nil {
			if ferr := publishedInFuture(p, now); ferr != nil {
				p, err = nil, inventory.NotOpened(filepath.Join(cp.dir, persistedName), ferr)
			}
		}
		var pa *publishedAhead
		switch {
		case ctx.Err() != nil:
			return nil
		case err == nil:
			return p
		case errors.As(err, &pa):
			ahead = append(ahead, cp)
			m.InventoryBundleRefused.Set(1)
			if again {
				return nil
			}
			say("inventory: %s is refused until this host's clock reaches it: %s\n", cp.name,
				oneLine(err))
		case errors.Is(err, inventory.ErrNotOpened):
			refusedOther = true
			m.InventoryBundleRefused.Set(1) // refused, said once, and alarmed (spec §10)
			say("inventory: %s is refused: %s\n", cp.name, oneLine(err))
		default:
			if cp.name == "the mirror's copy" {
				m.InventoryMirrorUnreadable.Set(1)
			}
			say("inventory: %s is passed over: %s\n", cp.name, oneLine(err))
		}
		why[cp.name] = oneLine(err)
		return nil
	}
	var picks []coldPick
	// choose keeps what judge made of cps, newer first, the earlier on a tie.
	// Every copy of a pass is held to one reading of the clock: a clock
	// stepped mid-pass would otherwise refuse the newer copy and take the
	// older one, judged a moment later.
	choose := func(cps []coldCopy, again bool) {
		now := coldNow()
		for _, cp := range cps {
			p := judge(cp, again, now)
			if p == nil {
				continue
			}
			if len(picks) == 0 || !p.Doc.PublishedAt.After(picks[0].p.Doc.PublishedAt) {
				picks = append(picks, coldPick{p, cp.name})
				continue
			}
			// Newer is later publication: a sequence starts again at 1
			// after a service reset, a publication time does not
			// (pre-flight minor 11). Only the mirror's copy follows the
			// persisted one.
			best := picks[0].p
			say("inventory: the mirror's bundle %d, published %s, is published later "+
				"than the persisted copy's bundle %d, published %s\n", p.Doc.Sequence,
				p.Doc.PublishedAt.Format(time.RFC3339), best.Doc.Sequence, best.Doc.PublishedAt.Format(time.RFC3339))
			picks = append([]coldPick{{p, cp.name}}, picks...)
		}
	}
	choose(copies, false)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	said := ""
	for len(picks) == 0 {
		rd.waiting()
		rctx, cancel := context.WithTimeout(ctx, requestTimeout)
		raw, _, _, err := c.Bundle(rctx, "")
		cancel()
		if err == nil {
			doc, inv, oerr := bundle.Open(raw, keys)
			p := &inventory.Published{Raw: raw, Doc: doc, Inv: inv}
			if oerr == nil {
				oerr = publishedInFuture(p, coldNow())
			}
			if oerr == nil {
				picks = []coldPick{{p, "the service"}}
				break
			}
			m.InventoryBundleRefused.Set(1)
			// Refused for anything but its date is a real refusal: a copy
			// the clock later reaches does not clear it.
			if pa := (*publishedAhead)(nil); !errors.As(oerr, &pa) {
				refusedOther = true
			}
			err = fmt.Errorf("its bundle is refused: %w", oerr)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// port49-broker holds back its API, port49d TACACS+ (Task 15a
		// review M-5).
		held := "TACACS+"
		if proc == "port49-broker" {
			held = "the API"
		}
		if line := fmt.Sprintf(proc+": inventory: no bundle yet (persisted copy: %s; mirror: %s; service at %s: %s); "+
			"%s is not served until one arrives, and /readyz answers 503 (spec §10, cold start)",
			why["the persisted copy"], why["the mirror's copy"], svc.URL, oneLine(err), held); line != said {
			fmt.Fprintln(stderr, line)
			said = line
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(svc.PollInterval):
		}
		// A copy refused only for the clock is judged again, read afresh
		// through the same path, now that the clock has moved.
		again := ahead
		ahead = nil
		choose(again, true)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if len(picks) > 0 && !refusedOther && len(ahead) == 0 {
			// Every refusal was of the clock, and the clock has caught up.
			m.InventoryBundleRefused.Set(0)
		}
	}
	if picks[0].from == "the service" {
		// The service sent the document now in force: whatever copy was
		// refused on the way is behind it.
		m.InventoryBundleRefused.Set(0)
	}
	return picks, nil
}

// startCopy is the copy the start serves (final review I2): the first of
// picks, newest first, that the policy in force loads with (loadPolicy, the
// start's own check), and, for the mirror's copy, that port49d's own
// inventory.max_removed_percent allows against the persisted copy, as it
// bounds a document the service sends. A copy passed over is said, with why,
// and alarmed; the fetcher offers the service's document through the bounded
// reload. Taking the newer copy blindly would exit on a policy that has not
// yet caught up with the source of truth — the whole-fleet re-address — and,
// had it been persisted, every restart after.
//
// With no copy the policy takes, the start fails on the last copy's
// refusal; each before it is said.
func startCopy(cfg config.Config, picks []coldPick, m *metrics.Metrics) (coldPick, error) {
	pols := make([]*policy.Policy, len(picks))
	errs := make([]error, len(picks))
	for i, pk := range picks {
		c := cfg
		c.Inventory = pk.p.Inv
		pols[i], errs[i] = loadPolicy(c, fmt.Sprintf("the inventory service's bundle %d", pk.p.Doc.Sequence))
	}
	for i, pk := range picks {
		err := errs[i]
		if err == nil && pk.from == "the mirror's copy" {
			for j := i + 1; j < len(picks); j++ {
				if picks[j].from == "the persisted copy" && errs[j] == nil {
					err = bundle.CheckFrom(pols[j], pols[i], cfg.MaxRemovedPercent, "fix the source of truth")
				}
			}
		}
		if err == nil {
			return pk, nil
		}
		if i == len(picks)-1 {
			return coldPick{}, err
		}
		m.InventoryBundleRefused.Set(1)
		fmt.Fprintf(stderr, procOf(cfg)+": inventory: %s, bundle %d, is not taken: %s; trying %s, bundle %d\n", pk.from,
			pk.p.Doc.Sequence, oneLine(quotesCut{err}), picks[i+1].from, picks[i+1].p.Doc.Sequence)
	}
	return coldPick{}, errors.New(procOf(cfg) + ": inventory: no copy to start from") // picks is never empty
}

// persistStart keeps the copy the start serves as port49d's own, once the
// policy and the broker have accepted it; the persisted copy is already
// there. A failure is said and alarmed, and the reloader tries again at the
// first confirmation (startDocument). proc is the process's name, as its
// lines begin (procOf).
func persistStart(proc string, svc *config.InventoryServiceConfig, pk coldPick, m *metrics.Metrics) {
	if pk.from == "the persisted copy" {
		return
	}
	if err := persistBundle(svc.StateDir, pk.p.Raw); err != nil {
		m.InventoryPersistFailed.Set(1)
		fmt.Fprintf(stderr, proc+": inventory: state_dir %s: %s; a restart with the service down will "+
			"need the mirror\n", svc.StateDir, oneLine(err))
	}
}

// sayStart is the start's line for the copy it serves, begun with proc.
func sayStart(proc string, svc *config.InventoryServiceConfig, pk coldPick) {
	fmt.Fprintf(stderr, proc+": inventory: starting from bundle %d (%s), published %s; the service at %s is "+
		"asked every %s\n", pk.p.Doc.Sequence, pk.from, pk.p.Doc.PublishedAt.Format(time.RFC3339), svc.URL,
		svc.PollInterval)
}
