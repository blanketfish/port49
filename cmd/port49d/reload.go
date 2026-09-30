package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/broker"
	"github.com/rhwendt/port49/internal/bundle"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/inventory"
	"github.com/rhwendt/port49/internal/keyring"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
)

// After a reload, and after a grant's expiry, the refresh runs twice: at
// once, and again settleAfterReload later. The second pass catches a login
// that spent a token the first pass was about to supersede and wrote its
// context after the first pass had visited it — a login in flight across the
// swap, or across the expiry, finishes on the answer it started with (plan
// 4b), and this is how its context is brought forward. refreshRetry is how
// soon a pass the store stopped is run again.
const (
	settleAfterReload = 30 * time.Second
	refreshRetry      = 30 * time.Second
	// stillChangingAfter is how many reads in a row the policy file may
	// differ at before the watch says it is not settling (reloader.poll).
	stillChangingAfter = 6
)

// reloader keeps the broker's bundle the one broker.policy_file (plan 4b) and
// inventory_file (plan 6a) make. It is one goroutine, so a reload, a poll and a scheduled refresh never run
// at once: every field below is its own.
//
// What an operator sees. A file that loads: one line naming the bundle it
// replaced and the one now in force, the quarantine and rule lines a start
// would print, and one line saying what the refresh did to live contexts. A
// file that does not: one line saying it was refused, why, and which bundle
// is still serving, once per distinct content, with port49_policy_file_refused
// at 1 until the file loads or is put back. A file someone else could have
// written is refused the same way (readPolicyFile). A refresh the store
// stopped: one line with how far it got and when it will try again; the
// policy is in force for every mint regardless, and the contexts not yet
// reached keep their previous policy until then. The pass that completes
// after a stop always says so. port49_policy_refresh_pending is 1 from a swap
// or an expiry until the settle pass after it completes, and while any pass
// is owed a retry. The inventory file is watched the same way, behind the
// same fence (readInventoryFile), with port49_inventory_file_refused as its
// alarm; an edit to either that would take more than
// inventory.max_removed_percent of the fleet out of service, or all of it,
// is refused (bundle.Check, bundle.CheckAdmission). Nothing is half-applied:
// a refused edit leaves the bundle in force as it was, and a swap is one
// pointer (policy.Live).
type reloader struct {
	cfg      config.Config
	broker   *broker.Broker
	metrics  *metrics.Metrics
	now      func() time.Time
	interval time.Duration

	// priors are the policies in force since the last complete refresh, which
	// the next refresh compares the policy in force against (broker.Prior).
	priors []broker.Prior
	// due is when the next refresh runs; zero is never (reschedule).
	due time.Time
	// expiry is the next grant expiry after the instant the last complete
	// pass judged at; settle is when the settle pass after a swap or an
	// expiry is due, zero once it has completed; retry is when a stopped pass
	// runs again, zero when none stopped. Zero is none.
	expiry, settle, retry time.Time
	// pending is a changed file's version seen by one poll, waiting for the
	// next to agree: an editor writing in place is not read half-way.
	pending string
	// refused is the version last refused, so a refusal is said once.
	refused string
	// changing counts the reads in a row that found a version differing from
	// the one before, so a file that never settles is said once.
	changing int
	// inventory is the inventory file's version in force (inventoryVersion),
	// and invPending, invRefused and invChanging are what pending, refused
	// and changing are to the policy file, for the inventory file.
	inventory, invPending, invRefused string
	invChanging                       int
	// cfgPath is port49d.yaml, whose inventory.max_removed_percent SIGHUP
	// re-reads (plan 6a, I1); run sets it.
	cfgPath string
	// seen and held are the daemon's key-version marks and the packets it
	// holds for keys diagnose; each swap forgets the devices the new bundle
	// no longer admits under the key_ref they were seen on (plan 6a final
	// review m6). Either may be nil; run sets them.
	seen *keyring.Seen
	held *keyring.Held
	// invSeen is when the inventory file was last read and found in force,
	// or loaded: port49_inventory_snapshot_age_seconds reads it at scrape.
	invSeen atomic.Int64
	// Service mode (inventory.service): inForce is the etag of the document
	// in force, seq its sequence, inForceAt its published_at, and latestRaw
	// its sealed bytes, which a persist that failed is retried with
	// (pre-flight M7).
	inForce   string
	seq       int64
	inForceAt time.Time
	latestRaw []byte
	// docs is what the fetcher hands over, and poke asks it to fetch the
	// document again at SIGHUP; both nil in file mode, where a receive
	// never fires and a poke is dropped (startFetcher).
	docs <-chan received
	poke chan<- struct{}
	// docRefused is the etag of the document last refused, so a refusal is
	// said once per document; persistSaid is the persist failure last said;
	// persistOwed is set while latestRaw may not be state_dir's copy — a
	// start from a copy other than the persisted one, whose persist at start
	// may have failed, or a persist that failed since — so the service's next
	// confirmation writes it (pre-flight M7).
	docRefused, persistSaid string
	persistOwed             bool
	// docPolicy is the policy_sha256 the document in force was built
	// against, and mismatch the pair of hashes last said to differ, so a
	// mismatch is said once per pair (sayPolicyMatch).
	docPolicy, mismatch string
	// latest is the last document the service sent, held so SIGHUP can try it
	// again under a raised bound or new verify keys; latestAhead is set while
	// its only refusal was a published_at ahead of this clock.
	latest      *received
	latestAhead bool
	// verifyKeys are the service's public keys in force: the fetcher opens
	// under them, and SIGHUP replaces them (rereadVerifyKeys).
	verifyKeys atomic.Pointer[[]ed25519.PublicKey]
	// stopped is set while the last refresh pass did not complete, so the
	// one that does says so whatever it found.
	stopped bool
}

func newReloader(cfg config.Config, b *broker.Broker, m *metrics.Metrics, now func() time.Time) *reloader {
	start := now()
	r := &reloader{cfg: cfg, broker: b, metrics: m, now: now, interval: cfg.Broker.PolicyWatchInterval,
		priors: []broker.Prior{{Policy: b.Policy.Load(), At: start}}}
	// run sets the version the start loaded; this is a test's. In service
	// mode there is no inventory file.
	if cfg.InventoryFile != "" {
		_, r.inventory, _ = inventoryVersion(cfg.InventoryFile)
	}
	r.expiry, _ = b.Policy.Load().NextChange(start)
	r.reschedule()
	r.invSeen.Store(start.UnixNano())
	// Never negative: a document dated a little ahead of this clock, within
	// maxPublishedSkew, is as fresh as can be, not younger than now.
	m.WatchInventoryAge(func() float64 { return max(now().Sub(time.Unix(0, r.invSeen.Load())).Seconds(), 0) })
	return r
}

// startDocument records the document the start loaded — its etag and
// sequence, so the fetcher's first unchanged answer confirms it — and dates
// the snapshot. A copy, persisted or mirrored, confirms nothing: the age
// counts from its publication, which may overstate it, the safe direction,
// until the first confirmation (spec §10; pre-flight M5). From the service,
// the start is itself a confirmation.
func (r *reloader) startDocument(p *inventory.Published, from string) {
	if p == nil {
		return
	}
	r.inForce, r.seq, r.inForceAt, r.latestRaw = bundle.ETag(p.Raw), p.Doc.Sequence, p.Doc.PublishedAt, p.Raw
	r.docPolicy = p.Doc.PolicySHA256
	// The persisted copy is state_dir's already; any other may not have
	// been written there (cold start says so if it failed).
	r.persistOwed = from != "the persisted copy"
	seen := r.now()
	if from != "the service" {
		seen = p.Doc.PublishedAt
	}
	r.invSeen.Store(seen.UnixNano())
	r.sayPolicyMatch()
}

// sayPolicyMatch compares the policy the service built the document in force
// against with the policy in force (spec §13, decision 29). A difference is
// never applied — the inventory is loaded against port49d's own policy — but
// it is said once per pair of hashes, and port49_inventory_policy_mismatch is
// 1 until they agree, which is said too. A rollout in progress holds it
// briefly; one that stays names a service or a daemon deployed from another
// commit of the policy repository.
func (r *reloader) sayPolicyMatch() {
	if r.docPolicy == "" {
		return
	}
	mine := r.broker.Policy.Load().Source
	if r.docPolicy == mine {
		r.metrics.InventoryPolicyMismatch.Set(0)
		if r.mismatch != "" {
			r.mismatch = ""
			fmt.Fprintf(stderr, "port49d: inventory: the service's policy and the policy in force agree again (%s)\n", mine)
		}
		return
	}
	r.metrics.InventoryPolicyMismatch.Set(1)
	if key := r.docPolicy + " " + mine; key != r.mismatch {
		r.mismatch = key
		fmt.Fprintf(stderr, "port49d: inventory: the service built bundle %d against policy %s, and the policy in "+
			"force is %s; its inventory is applied against the policy in force, and nothing the service sends changes "+
			"the policy (spec §13, decision 29)\n", r.seq, r.docPolicy, mine)
	}
}

// inventoryVersion is policyVersion for inventory_file: read behind the fence
// (readInventoryFile), so a file someone else could have written is a
// version of its own — refused, and said once — and putting its mode right
// is a change the watch sees. A named pipe is refused, never waited on.
func inventoryVersion(path string) ([]byte, string, error) {
	raw, err := readInventoryFile(path)
	if err != nil {
		return nil, "unreadable: " + err.Error(), err
	}
	return raw, engine.HashOf(raw), nil
}

// policyVersion is the policy file's content and a string that changes when it
// does — its sha256, or why it could not be read — read as the start reads it
// (readPolicyFile): the version of a file that loads is the bundle it loads
// as, and a file someone else could have written is a version of its own —
// refused, and said once — so putting its mode right is a change the watch
// sees.
func policyVersion(path string) ([]byte, string, error) {
	raw, err := readPolicyFile(path)
	if err != nil {
		return nil, "unreadable: " + err.Error(), err
	}
	return raw, engine.HashOf(raw), nil
}

// run serves until ctx ends: a poll every interval, a reload at every SIGHUP,
// and the refresh schedule.
func (r *reloader) run(ctx context.Context, hup <-chan os.Signal) {
	tick := time.NewTicker(r.interval)
	defer tick.Stop()
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	for {
		arm(timer, r.due, r.now())
		select {
		case <-ctx.Done():
			return
		case <-hup:
			r.reload(ctx, "SIGHUP")
		case d := <-r.docs:
			r.receive(ctx, d)
		case <-tick.C:
			r.poll(ctx)
		case <-timer.C:
			r.refresh(ctx)
		}
	}
}

// arm sets timer to fire at due, or not at all for a zero due.
func arm(timer *time.Timer, due, now time.Time) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	if !due.IsZero() {
		timer.Reset(max(due.Sub(now), 0))
	}
}

// poll reads both files, the policy first; in service mode there is no
// inventory file to read.
func (r *reloader) poll(ctx context.Context) {
	r.pollPolicy(ctx)
	if r.cfg.InventoryService == nil {
		r.pollInventory(ctx)
	}
}

// pollPolicy reads the policy file and loads it once two reads in a row agree
// on a version that is neither the one in force nor one already refused. What
// it loads is the second read's bytes, the ones the two reads agreed on: read
// again, a file an editor began writing in between would be loaded half-way.
func (r *reloader) pollPolicy(ctx context.Context) {
	raw, v, err := policyVersion(r.cfg.Broker.PolicyFile)
	switch {
	case v == r.broker.Policy.Load().Source:
		// The file in force ends a run of differing reads: blips days
		// apart — a file missing for a moment in a ConfigMap swap — must
		// not add up to the never-settles alarm.
		alarmed := r.changing >= stillChangingAfter
		r.pending, r.changing = "", 0
		if r.refused != "" || alarmed {
			r.refused = ""
			r.metrics.PolicyFileRefused.Set(0)
			fmt.Fprintf(stderr, "port49d: policy: broker.policy_file %s is the policy in force again (%s, bundle %s)\n",
				r.cfg.Broker.PolicyFile, v, r.broker.Policy.Load().Bundle)
		}
	case v == r.refused:
		r.pending, r.changing = "", 0
	case v != r.pending:
		// A file that changes at every read never has two agree, so it
		// never loads: two tools fighting over it, or a templater stamping
		// the time. Say so once, and hold the alarm, rather than leave an
		// operator believing the edit is live.
		r.pending = v
		if r.changing++; r.changing == stillChangingAfter {
			r.metrics.PolicyFileRefused.Set(1)
			fmt.Fprintf(stderr, "port49d: policy: broker.policy_file %s has changed at each of the last %d reads, "+
				"%s apart, so it is not loaded; still serving %s (bundle %s); write it once, atomically\n",
				r.cfg.Broker.PolicyFile, stillChangingAfter, r.interval, r.broker.Policy.Load().Source,
				r.broker.Policy.Load().Bundle)
		}
	default:
		r.pending = ""
		r.load(ctx, "file changed", raw, v, err)
	}
}

// pollInventory is pollPolicy for inventory_file (spec §10): a changed file
// is loaded once two reads in a row agree, a refused one is said once, and
// one that never settles is said and alarmed.
func (r *reloader) pollInventory(ctx context.Context) {
	raw, v, err := inventoryVersion(r.cfg.InventoryFile)
	switch {
	case v == r.inventory:
		r.invSeen.Store(r.now().UnixNano())
		alarmed := r.invChanging >= stillChangingAfter
		r.invPending, r.invChanging = "", 0
		if r.invRefused != "" || alarmed {
			r.invRefused = ""
			r.metrics.InventoryFileRefused.Set(0)
			fmt.Fprintf(stderr, "port49d: inventory: inventory_file %s is the inventory in force again (bundle %s)\n",
				r.cfg.InventoryFile, r.broker.Policy.Load().Bundle)
		}
	case v == r.invRefused:
		r.invPending, r.invChanging = "", 0
	case v != r.invPending:
		r.invPending = v
		if r.invChanging++; r.invChanging == stillChangingAfter {
			r.metrics.InventoryFileRefused.Set(1)
			fmt.Fprintf(stderr, "port49d: inventory: inventory_file %s has changed at each of the last %d reads, "+
				"%s apart, so it is not loaded; still serving bundle %s; write it once, atomically\n",
				r.cfg.InventoryFile, stillChangingAfter, r.interval, r.broker.Policy.Load().Bundle)
		}
	default:
		r.invPending = ""
		r.loadInventory(ctx, "inventory file changed", raw, v, err)
	}
}

// reload reads each file once and loads what it read: SIGHUP's path, with no
// second read, because the operator asked. It re-reads the bound and the
// verify keys first, so raising the bound, or adding the service's new key,
// and sending SIGHUP applies a change refused before, and it loads the
// inventory whenever its version is not the one in force, so a refused
// inventory is tried again. In service mode that is the latest document the
// service sent, and the fetcher is asked to fetch the document again.
func (r *reloader) reload(ctx context.Context, trigger string) {
	r.rereadBound()
	r.rereadVerifyKeys()
	// (Task 17: the combined check of both sources goes here.)
	raw, v, err := policyVersion(r.cfg.Broker.PolicyFile)
	r.load(ctx, trigger, raw, v, err)
	if r.cfg.InventoryService != nil {
		if d := r.latest; d != nil && d.etag != r.inForce {
			r.docRefused = ""
			r.loadDocument(ctx, trigger, *d)
		}
		select {
		case r.poke <- struct{}{}:
		default:
		}
		return
	}
	iraw, iv, ierr := inventoryVersion(r.cfg.InventoryFile)
	if iv != r.inventory {
		r.invPending = ""
		r.loadInventory(ctx, trigger, iraw, iv, ierr)
	}
}

// rereadBound re-reads inventory.max_removed_percent from port49d.yaml, the
// one key SIGHUP re-reads, so a deliberate large removal needs no restart
// (plan 6a, I1). A file that does not read keeps the bound in force, said.
func (r *reloader) rereadBound() {
	if r.cfgPath == "" {
		return
	}
	// Read as a regular file only, non-blocking and bounded: a named pipe
	// here would block the reloader, and with it every poll, every refresh
	// and shutdown (plan 6a Task 12, m3).
	raw, err := config.ReadRegular(r.cfgPath, config.MaxConfigSize)
	var n int
	if err == nil {
		n, err = config.InventoryBound(raw)
	}
	switch {
	case err != nil:
		fmt.Fprintf(stderr, "port49d: SIGHUP: inventory.max_removed_percent not re-read from %s (%s); keeping %d%%\n",
			r.cfgPath, oneLine(err), r.cfg.MaxRemovedPercent)
	case n != r.cfg.MaxRemovedPercent:
		fmt.Fprintf(stderr, "port49d: SIGHUP: inventory.max_removed_percent is now %d%% (was %d%%)\n", n,
			r.cfg.MaxRemovedPercent)
		r.cfg.MaxRemovedPercent = n
	}
}

// receive is one thing the fetcher handed over: a confirmation of the
// document in force, which keeps the snapshot young, or a document, which is
// loaded as a reload. The document in force sent whole again — the fetch a
// SIGHUP asks for — is a confirmation too. The service confirming a document
// refused only for being published ahead of this clock judges it again, as
// cold start judges such a copy at each pass (spec §10).
func (r *reloader) receive(ctx context.Context, d received) {
	if d.etag == r.inForce {
		r.confirmed()
		return
	}
	if d.unchanged {
		if l := r.latest; l != nil && r.latestAhead && d.etag == l.etag {
			r.loadDocument(ctx, "inventory service", *l)
		}
		return
	}
	r.latest = &d
	r.loadDocument(ctx, "inventory service", d)
}

// confirmed is the service confirming the document in force: the snapshot
// is young again, nothing it sent is pending refusal, a cold start's refused
// copy is behind us (Task 14), and a persist owed is tried again, at every
// confirmation rather than only at the next document (pre-flight M7). A
// document in force that no longer opens under the verify keys in force — a
// SIGHUP removed its signer — confirms nothing: it keeps serving, since
// nothing else is at hand, but port49_inventory_bundle_refused stays 1, said
// once, until the service sends one that opens.
func (r *reloader) confirmed() {
	r.invSeen.Store(r.now().UnixNano())
	if keys := r.verifyKeys.Load(); r.latestRaw != nil && keys != nil {
		if _, _, err := bundle.Open(r.latestRaw, *keys); err != nil {
			r.metrics.InventoryBundleRefused.Set(1)
			if r.docRefused != r.inForce {
				r.docRefused = r.inForce
				fmt.Fprintf(stderr, "port49d: inventory: bundle %d, in force, no longer opens under the verify keys "+
					"in force (%s); it keeps serving until the service sends a document that does, and "+
					"port49_inventory_bundle_refused stays 1\n", r.seq, oneLine(quotesCut{err}))
			}
			return
		}
	}
	r.docRefused = ""
	r.metrics.InventoryBundleRefused.Set(0)
	if r.persistOwed && r.latestRaw != nil {
		r.persist(r.latestRaw)
	}
}

// openDocument opens raw, a document the service sent, and judges it
// against the one in force. EVERY PATH THAT APPLIES A SERVICE DOCUMENT GOES
// THROUGH IT, at the moment it applies: loadDocument, and any reload that
// combines both sources (Task 17). Nothing opened earlier — by the fetcher,
// or at a SIGHUP before — is trusted, since a key this SIGHUP removed must
// not apply a document (ruling 1).
//
// It opens raw under the verify keys in force now, then refuses a document
// published more than maxPublishedSkew ahead of this clock (a
// *publishedAhead, which would outrank every later copy at a cold start;
// spec §10), and one not later than the document in force by (published_at,
// sequence): a later published_at, or the same with a higher sequence. A
// service whose state_dir was reset publishes later, so its sequence may go
// back (Decided 3); published_at is signed and survives the reset, so an
// older genuine document replayed — from before the reset too — is refused.
//
// pub is non-nil whenever raw opened, refused or not, so the caller can name
// its sequence; it is safe to apply only when err is nil.
func (r *reloader) openDocument(raw []byte) (*inventory.Published, error) {
	var keys []ed25519.PublicKey
	if k := r.verifyKeys.Load(); k != nil {
		keys = *k
	}
	doc, inv, err := bundle.Open(raw, keys)
	switch {
	case errors.Is(err, bundle.ErrUnknownKey):
		return nil, fmt.Errorf("the document does not open (%w); if the service's signing key was rotated, add "+
			"its public key to inventory.service.verify_key_files and send SIGHUP", err)
	case err != nil:
		// Not a rotation: a signature that does not verify under a key
		// port49d holds is tampering or a foreign signer (pre-flight minor 4).
		return nil, fmt.Errorf("the document does not open (%w); it was not signed by any key port49d holds for "+
			"the service: investigate", err)
	}
	pub := &inventory.Published{Raw: raw, Doc: doc, Inv: inv}
	if err := publishedInFuture(pub, r.now()); err != nil {
		return pub, err
	}
	if !doc.PublishedAt.After(r.inForceAt) && !(doc.PublishedAt.Equal(r.inForceAt) && doc.Sequence > r.seq) {
		return pub, fmt.Errorf("bundle %d, published %s, is not later than bundle %d in force, published %s: an "+
			"older document sent again, or the service's clock went back; investigate the service and whoever "+
			"can answer as it", doc.Sequence, doc.PublishedAt.Format(time.RFC3339), r.seq,
			r.inForceAt.Format(time.RFC3339))
	}
	return pub, nil
}

// loadDocument puts the service's document in force, as loadInventory puts a
// file (spec §10): opened and judged by openDocument, parsed against the
// policy in force, bounded by inventory.max_removed_percent, swapped in one
// pointer, its security changes recorded, the refresh run, and the document
// persisted. d.pub and d.err are not read. One that does not open or does
// not pass changes nothing, is said once per document, and holds
// port49_inventory_bundle_refused at 1. Each refusal is counted, except one
// judged again only because the service confirmed it while it is still
// ahead of this clock: that is counted once per document, not once per poll.
func (r *reloader) loadDocument(ctx context.Context, trigger string, d received) {
	old := r.broker.Policy.Load()
	label := trigger
	var pol *policy.Policy
	pub, err := r.openDocument(d.raw)
	if pub != nil {
		label = fmt.Sprintf("%s, bundle %d", trigger, pub.Doc.Sequence)
	}
	var pa *publishedAhead
	ahead := errors.As(err, &pa)
	stillAhead := ahead && r.latestAhead && d.etag == r.docRefused
	r.latestAhead = ahead
	if err == nil {
		pol, err = bundle.Parse(old.Raw(), pub.Inv, policy.Env{KeyRefs: r.cfg.KeyRefs()})
	}
	if err == nil {
		err = bundle.CheckFrom(old, pol, r.cfg.MaxRemovedPercent, "fix the source of truth")
	}
	if err != nil {
		if !stillAhead {
			r.metrics.InventoryReloads.WithLabelValues("refused").Inc()
		}
		r.metrics.InventoryBundleRefused.Set(1)
		if d.etag != r.docRefused {
			r.docRefused = d.etag
			fmt.Fprintf(stderr, "port49d: inventory reload (%s) refused; still serving bundle %s (%d): %s\n", label,
				old.Bundle, r.seq, oneLine(quotesCut{err}))
		}
		return
	}
	r.docRefused = ""
	r.metrics.InventoryBundleRefused.Set(0)
	if pub.Doc.Sequence < r.seq {
		fmt.Fprintf(stderr, "port49d: inventory: the service's sequence went back from %d to %d: its state_dir was "+
			"reset; applying it (spec §10)\n", r.seq, pub.Doc.Sequence)
	}
	r.inForce, r.seq, r.inForceAt, r.latestRaw = bundle.ETag(d.raw), pub.Doc.Sequence, pub.Doc.PublishedAt, d.raw
	r.docPolicy = pub.Doc.PolicySHA256
	r.invSeen.Store(r.now().UnixNano())
	r.metrics.InventoryBundleSequence.Set(float64(r.seq))
	r.persist(d.raw)
	if pol.Bundle == old.Bundle {
		// The same devices under a new sequence: nothing to swap.
		r.metrics.InventoryReloads.WithLabelValues("unchanged").Inc()
		r.sayPolicyMatch()
		return
	}
	r.metrics.InventoryReloads.WithLabelValues("applied").Inc()
	now := r.swap(pol)
	r.refused = ""
	rep := bundle.Diff(old, pol, now)
	fmt.Fprintf(stderr, "port49d: inventory reloaded (%s): %s; %d device(s) quarantined now, %d before; %d refused "+
		"admission\n", label, rep.Summary(), quarantinedAt(pol, now), quarantinedAt(old, now), len(pol.AdmissionRefusals()))
	r.after(ctx, "inventory", rep, pol, now)
	r.sayPolicyMatch()
}

// persist keeps raw as port49d's copy, atomically (persistBundle); a failure
// is said once and alarmed, owed to the next confirmation, and serving goes
// on.
func (r *reloader) persist(raw []byte) {
	if err := persistBundle(r.cfg.InventoryService.StateDir, raw); err != nil {
		r.persistOwed = true
		if r.metrics.InventoryPersistFailed.Set(1); r.persistSaid != oneLine(err) {
			r.persistSaid = oneLine(err)
			fmt.Fprintf(stderr, "port49d: inventory: state_dir %s: %s; a restart with the service down would start "+
				"from an older copy\n", r.cfg.InventoryService.StateDir, r.persistSaid)
		}
		return
	}
	r.persistSaid, r.persistOwed = "", false
	r.metrics.InventoryPersistFailed.Set(0)
}

// rereadVerifyKeys re-reads inventory.service.verify_key_files from
// port49d.yaml at SIGHUP (Decided 12), behind the write fence
// (config.VerifyKeys). A file that does not read keeps the keys in force,
// said. The inventory source is read at start only: a port49d.yaml whose
// inventory.service block was removed, or whose other keys changed, is said
// and changes nothing — never read as no verify keys.
func (r *reloader) rereadVerifyKeys() {
	if r.cfgPath == "" {
		return
	}
	raw, err := config.ReadRegular(r.cfgPath, config.MaxConfigSize)
	var svc *config.InventoryServiceConfig
	if err == nil {
		svc, err = config.InventoryServiceOf(raw)
	}
	if r.cfg.InventoryService == nil {
		if err == nil && svc != nil {
			fmt.Fprintf(stderr, "port49d: SIGHUP: %s has an inventory.service block; the inventory source is read at "+
				"start only; still reading inventory_file %s\n", r.cfgPath, r.cfg.InventoryFile)
		}
		return
	}
	var keys []ed25519.PublicKey
	if err == nil && svc != nil {
		keys, err = config.VerifyKeys(svc.VerifyKeyFiles)
	}
	switch {
	case err != nil:
		fmt.Fprintf(stderr, "port49d: SIGHUP: inventory.service.verify_key_files not re-read from %s (%s); keeping "+
			"the keys in force\n", r.cfgPath, oneLine(err))
	case svc == nil:
		fmt.Fprintf(stderr, "port49d: SIGHUP: %s has no inventory.service block; the inventory source is read at "+
			"start only; keeping the service and the keys in force\n", r.cfgPath)
	default:
		r.verifyKeys.Store(&keys)
		fmt.Fprintf(stderr, "port49d: SIGHUP: %d inventory verify key(s) in force\n", len(keys))
		if cur := r.cfg.InventoryService; svc.URL != cur.URL || svc.CAFile != cur.CAFile ||
			svc.TLSCertFile != cur.TLSCertFile || svc.TLSKeyFile != cur.TLSKeyFile || svc.StateDir != cur.StateDir ||
			svc.MirrorDir != cur.MirrorDir || svc.PollInterval != cur.PollInterval {
			fmt.Fprintf(stderr, "port49d: SIGHUP: inventory.service in %s differs from the one in force beyond "+
				"verify_key_files; those keys are read at start only, so still asking %s every %s\n", r.cfgPath,
				cur.URL, cur.PollInterval)
		}
	}
}

// load puts raw, the policy file's content read as version v, in force and
// refreshes, if it loads and passes the admission bound. A file that does
// not, or could not be read (err), changes nothing.
func (r *reloader) load(ctx context.Context, trigger string, raw []byte, v string, err error) {
	r.changing = 0
	old := r.broker.Policy.Load()
	var pol *policy.Policy
	if err == nil && v == old.Source {
		// The bytes in force: nothing to compile, and nothing is refused
		// that was loaded before (a SIGHUP with no edit).
		pol = old
	} else if err == nil {
		pol, err = parseBundle(r.cfg, raw, old.Inventory())
		if err == nil {
			// Key groups are policy, and a refused device's sessions are
			// revoked and its tokens deleted (I2): a key_groups typo must
			// not log out the fleet (plan 6a, N1). A policy that admits no
			// device is refused whatever the bound.
			if err = bundle.CheckAdmission(old, pol, r.cfg.MaxRemovedPercent); err != nil {
				err = fmt.Errorf("broker.policy_file %s: %w", r.cfg.Broker.PolicyFile, err)
			}
		}
	} else {
		err = fmt.Errorf("broker.policy_file %s: %w", r.cfg.Broker.PolicyFile, err)
	}
	if err != nil {
		r.metrics.PolicyReloads.WithLabelValues("refused").Inc()
		r.metrics.PolicyFileRefused.Set(1)
		r.refused = v
		fmt.Fprintf(stderr, "port49d: policy reload (%s) refused; still serving %s (bundle %s): %s\n", trigger,
			old.Source, old.Bundle, oneLine(err))
		return
	}
	r.refused = ""
	r.metrics.PolicyFileRefused.Set(0)
	if pol.Source == old.Source {
		r.metrics.PolicyReloads.WithLabelValues("unchanged").Inc()
		fmt.Fprintf(stderr, "port49d: policy reload (%s): broker.policy_file unchanged, %s in force (bundle %s)\n",
			trigger, pol.Source, pol.Bundle)
		return
	}
	r.metrics.PolicyReloads.WithLabelValues("applied").Inc()
	now := r.swap(pol)
	// An inventory edit refused against the policy replaced — the key-group
	// move done in the wrong order, say — is tried again against this one at
	// the next polls (plan 6a, C3).
	r.invRefused = ""
	fmt.Fprintf(stderr, "port49d: policy reloaded (%s): %s replaces %s (bundle %s); %d device(s) quarantined now, %d before\n",
		trigger, pol.Source, old.Source, pol.Bundle, quarantinedAt(pol, now), quarantinedAt(old, now))
	r.after(ctx, "policy", bundle.Diff(old, pol, now), pol, now)
	r.sayPolicyMatch()
}

// loadInventory builds a bundle from raw, the inventory file read as version
// v, and the policy in force, and puts it in force if it loads and passes the
// bounded-change check (spec §10). One that does not changes nothing: the
// bundle in force keeps serving, the refusal is said once per version, and
// port49_inventory_file_refused is 1 until a file loads or the one in force
// is put back.
func (r *reloader) loadInventory(ctx context.Context, trigger string, raw []byte, v string, err error) {
	r.invChanging = 0
	old := r.broker.Policy.Load()
	var pol *policy.Policy
	if err == nil {
		pol, err = r.inventoryBundle(old, raw)
	} else {
		err = fmt.Errorf("inventory_file %s: %w", r.cfg.InventoryFile, err)
	}
	if err != nil {
		r.metrics.InventoryReloads.WithLabelValues("refused").Inc()
		r.metrics.InventoryFileRefused.Set(1)
		r.invRefused = v
		fmt.Fprintf(stderr, "port49d: inventory reload (%s) refused; still serving bundle %s: %s\n", trigger,
			old.Bundle, oneLine(err))
		return
	}
	r.inventory, r.invRefused = v, ""
	r.invSeen.Store(r.now().UnixNano())
	r.metrics.InventoryFileRefused.Set(0)
	if pol.Bundle == old.Bundle {
		// The same devices, respelled: nothing to swap.
		r.metrics.InventoryReloads.WithLabelValues("unchanged").Inc()
		fmt.Fprintf(stderr, "port49d: inventory reload (%s): the same inventory, respelled; bundle %s in force\n",
			trigger, old.Bundle)
		return
	}
	r.metrics.InventoryReloads.WithLabelValues("applied").Inc()
	now := r.swap(pol)
	// A policy edit refused against the inventory replaced is tried again
	// against this one at the next polls, as the other way round (C3).
	r.refused = ""
	rep := bundle.Diff(old, pol, now)
	fmt.Fprintf(stderr, "port49d: inventory reloaded (%s): %s; %d device(s) quarantined now, %d before; %d refused "+
		"admission\n", trigger, rep.Summary(), quarantinedAt(pol, now), quarantinedAt(old, now),
		len(pol.AdmissionRefusals()))
	r.after(ctx, "inventory", rep, pol, now)
}

// inventoryBundle is the bundle raw, the inventory file's bytes, makes with
// the policy in force, if it parses and passes Check. A fault after the parse
// is named as the inventory's, not the policy file's: the policy in force
// loaded before (plan 6a, M5).
func (r *reloader) inventoryBundle(old *policy.Policy, raw []byte) (*policy.Policy, error) {
	inv, err := admission.ParseFile(raw, "") // the error below names the file
	if err != nil {
		return nil, fmt.Errorf("inventory_file %s: %w", r.cfg.InventoryFile, quotesCut{err})
	}
	pol, err := bundle.Parse(old.Raw(), inv, policy.Env{KeyRefs: r.cfg.KeyRefs()})
	if err == nil {
		err = bundle.Check(old, pol, r.cfg.MaxRemovedPercent)
	}
	if err != nil {
		return nil, fmt.Errorf("inventory_file %s, loaded against the policy in force: %w", r.cfg.InventoryFile,
			quotesCut{err})
	}
	return pol, nil
}

// swap puts pol in force and opens its span, as every reload does: Swap
// waits for the mints in flight, which finish on the bundle they started
// with, so the replaced bundle's span ends when it returns; the next grant
// expiry is read from pol, and a settle pass is owed.
func (r *reloader) swap(pol *policy.Policy) time.Time {
	r.broker.Policy.Swap(pol)
	assigned := func(device string) string {
		a, _ := pol.Admitted(device)
		return a.KeyRef
	}
	if r.seen != nil {
		r.seen.Keep(assigned)
	}
	if r.held != nil {
		r.held.Keep(assigned)
	}
	now := r.now()
	r.priors[len(r.priors)-1].Until = now
	r.priors = append(r.priors, broker.Prior{Policy: pol, At: now})
	r.expiry, _ = pol.NextChange(now)
	r.settle = now.Add(settleAfterReload)
	r.metrics.PolicyRefreshPending.Set(1)
	return now
}

// after is what every swap runs once its line is written: an inventory_change
// record for each security change it made, the lines a start would print, and
// the refresh that carries the bundle into live contexts. file, "policy" or
// "inventory", names the file whose swap it was: the security line's prefix
// says which file changed access.
func (r *reloader) after(ctx context.Context, file string, rep bundle.Report, pol *policy.Policy, now time.Time) {
	if n := r.securityEvents(rep, now); n > 0 {
		fmt.Fprintf(stderr, "port49d: %s: %d security change(s) written as inventory_change records "+
			"(spec §10)\n", file, n)
	}
	sayPolicy(pol, now)
	r.refresh(ctx)
}

// securityEvents writes one inventory_change record for each security change
// the swap made, and counts it (spec §5.7, §10). It returns how many.
func (r *reloader) securityEvents(rep bundle.Report, now time.Time) int {
	changes := rep.Security()
	for _, c := range changes {
		r.broker.Log.Emit(decision.Record{TS: now, Event: decision.EventInventoryChange,
			Device: &decision.Device{Name: c.Device, Platform: c.Platform},
			Change: &decision.Change{Kind: c.Kind, Scope: c.Scope, Address: c.Address, From: c.From, To: c.To,
				FromBundle: rep.From, ToBundle: rep.To}})
		r.metrics.InventoryChanges.WithLabelValues(c.Kind).Inc()
	}
	return len(changes)
}

// refresh runs one refresh pass and schedules the next. A pass the store
// stopped, or that left a context still changing, runs again refreshRetry
// from now. One that completed is scheduled from the instant it judged at
// (RefreshReport.At), not from the clock after it: the next grant expiry after
// that instant, which is due at once if it has already passed, and the settle
// pass settleAfterReload after a pass that crossed an expiry.
//
// port49_policy_refresh_pending is 1 from a swap or an expiry until the settle
// pass after it completes, and while a pass is owed a retry: while it is, a
// live context may still hold a policy no longer in force — a withdrawn or
// expired grant included.
func (r *reloader) refresh(ctx context.Context) {
	if !r.expiry.IsZero() && !r.now().Before(r.expiry) {
		// A grant has expired, and until this pass reaches every context
		// one may still hold it.
		r.metrics.PolicyRefreshPending.Set(1)
	}
	rep, err := r.broker.Refresh(ctx, r.priors)
	if err != nil && ctx.Err() != nil {
		return // port49d is shutting down: there is no retry to announce
	}
	if err != nil {
		r.stopped = true
		r.metrics.PolicyRefreshPending.Set(1)
		if errors.Is(err, store.ErrConflict) {
			// Every context was visited and the store answered: only the busy
			// ones, counted failed, are left.
			fmt.Fprintf(stderr, "port49d: policy refresh: %d context(s) still changing after every attempt keep "+
				"their previous policy (%s); trying them again in %s\n", rep.Failed, summary(rep), refreshRetry)
		} else {
			fmt.Fprintf(stderr, "port49d: policy refresh stopped (%s so far): %v; the contexts not reached keep "+
				"their previous policy; trying again in %s\n", summary(rep), err, refreshRetry)
		}
		r.retry = r.now().Add(refreshRetry)
		r.reschedule()
		return
	}
	cur := r.broker.Policy.Load()
	r.priors = []broker.Prior{{Policy: cur, At: rep.At}}
	r.retry = time.Time{}
	if !r.settle.IsZero() && !rep.At.Before(r.settle) {
		r.settle = time.Time{}
	}
	if !r.expiry.IsZero() && !rep.At.Before(r.expiry) {
		r.settle = rep.At.Add(settleAfterReload)
	}
	r.expiry, _ = cur.NextChange(rep.At)
	if r.settle.IsZero() {
		r.metrics.PolicyRefreshPending.Set(0)
	} else {
		r.metrics.PolicyRefreshPending.Set(1)
	}
	switch {
	case r.stopped:
		r.stopped = false
		fmt.Fprintf(stderr, "port49d: policy refresh finished: %s\n", summary(rep))
	case rep.Updated+rep.Revoked+rep.Quarantined+rep.Failed+rep.TokenKeys > 0:
		fmt.Fprintf(stderr, "port49d: policy refresh: %s\n", summary(rep))
	}
	r.reschedule()
}

// reschedule sets due. A retry owed comes first, and alone: that pass judges
// everything an expiry or a settle pass would, and a store still down must
// not be asked again at once for an expiry already past. Otherwise it is the
// earlier of the next expiry and the settle pass.
func (r *reloader) reschedule() {
	r.due = r.retry
	if r.due.IsZero() {
		r.due = r.expiry
		if r.due.IsZero() || (!r.settle.IsZero() && r.settle.Before(r.due)) {
			r.due = r.settle
		}
	}
}

// summary is what a refresh did, in one clause per count. A context updated or
// revoked on a platform that never asks about a command is counted, and said:
// its live session keeps what it had at login until logout, and the broker's
// process log names each one's ctx_id.
func summary(rep broker.RefreshReport) string {
	s := fmt.Sprintf("%d live context(s) updated, %d revoked, %d unchanged, %d left on quarantined devices, "+
		"%d failed", rep.Updated, rep.Revoked, rep.Unchanged, rep.Quarantined, rep.Failed)
	if rep.Unreached > 0 {
		s += fmt.Sprintf("; %d of them on platforms that do not authorize commands keep their live session until "+
			"logout (spec §13 decision 21)", rep.Unreached)
	}
	return s + fmt.Sprintf("; unspent tokens superseded on %d (device, username) key(s)", rep.TokenKeys)
}

// oneLine is err's text on one line, the way port49d's other lines are: a YAML
// error lists what it found on lines of its own.
func oneLine(err error) string {
	lines := strings.Split(err.Error(), "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	return strings.ReplaceAll(strings.Join(lines, "; "), ":; ", ": ")
}

// quarantinedAt counts the devices p quarantines at now.
func quarantinedAt(p *policy.Policy, now time.Time) int {
	n := 0
	for _, q := range p.Quarantines(now) {
		for _, e := range q.Entries {
			if e.Current(now) {
				n++
				break
			}
		}
	}
	return n
}
