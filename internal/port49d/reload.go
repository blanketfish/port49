package port49d

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
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
	"github.com/rhwendt/port49/internal/store"
)

// After a reload, and after a grant's expiry, the refresh runs twice: at
// once, and again settleAfter later. The second pass catches a login that
// spent a token the first pass was about to supersede and wrote its
// context after the first pass had visited it — a login in flight across the
// swap, or across the expiry, finishes on the answer it started with (plan
// 4b), and this is how its context is brought forward. refreshRetry is how
// soon a pass the store stopped is run again.
const (
	settleMin    = 30 * time.Second
	refreshRetry = 30 * time.Second
	// stillChangingAfter is how many reads in a row the policy file may
	// differ at before the watch says it is not settling (reloader.poll).
	stillChangingAfter = 6
)

// settleAfter is how long after a swap or an expiry the settle pass runs:
// settleMin, or two watch intervals and 5s when that is longer, so a
// replica that reads the file one interval late, and polls twice before it
// loads, has reloaded by then (plan 7e, Ruling 8).
func settleAfter(interval time.Duration) time.Duration {
	return max(settleMin, 2*interval+5*time.Second)
}

// reloader keeps the bundle in force the one the policy file (plan 4b) and
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
	cfg config.Config
	// proc names the process its lines are said for, procOf(cfg) when
	// empty: tests set it, a broker's key_refs being config.Load's alone.
	proc string
	// live is the policy in force, which a reload swaps; log is where its
	// inventory_change records go.
	live *policy.Live
	log  decision.Emitter
	// pass is the refresh pass that carries a swap into the live contexts
	// (broker.Broker.Refresh), nil with no broker in the process (plan 7e):
	// port49d alone reads the policy in force at each packet, and carries
	// nothing.
	pass     func(ctx context.Context, priors []broker.Prior) (broker.RefreshReport, error)
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
	// together is the pair of versions, policy and inventory, last refused
	// together, so a combined refusal is said once per pair (loadBoth).
	together string
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
	// rejudged is the etag of the document a SIGHUP judged again and asked
	// the fetcher for once more, until the next whole document arrives.
	rejudged string
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
	// onSettled is told the policy in force after each complete pass that
	// leaves nothing pending: port49-broker's runner records it as judged
	// (plan 7e, Ruling 7). Nil tells no one.
	onSettled func(pol *policy.Policy)
	// owed is how a start that left a pass owed tells run, from another
	// goroutine: true for a pass at once (startLeft). run is the only
	// caller of startLeft once it runs.
	owed chan bool
	// onSwap is told each policy a swap put in force, after the swap, on
	// this goroutine: port49-broker records the bundle it serves and asks
	// the runner for a full context pass (plan 7e, Ruling 8 corrected). It
	// must not wait. Nil tells no one.
	onSwap func(pol *policy.Policy)
	// onHUP is told each SIGHUP before the reload: the TLS listener's files
	// are re-read then too (decision 50 ruling 15). Nil is nothing.
	onHUP func()
	// beforeSwap is told each policy about to be put in force, before it is:
	// the TLS listener flags the devices the new inventory makes
	// unidentifiable before any connection can be admitted under it. It must
	// not wait. Nil tells no one.
	beforeSwap func(pol *policy.Policy)
	// mfaUnavailable is the broker's ruling 18 statement for a policy put in
	// force (broker.Broker.MFAUnavailable), said after each swap when it is
	// not empty. Nil with no broker in the process.
	mfaUnavailable func(pol *policy.Policy, now time.Time) string
	// fullPass is how the runner's duties hand run a full context pass a
	// replica owes (runner.owed), which whole runs (full). Both are
	// port49-broker's; elsewhere fullPass is nil, and a receive never fires.
	fullPass chan fullPassOwed
	whole    func(ctx context.Context, priors []broker.Prior) (broker.RefreshReport, error)
}

// fullPassOwed is a full context pass the runner owes: who asked, or why
// it is owed, already safe to print, and the bundle it served. done is
// told the pass's error, nil once it completed.
type fullPassOwed struct {
	who, bundle string
	done        chan<- error
}

// sayf writes one of the reloader's lines to stderr, format ending in its
// newline, prefixed with the name of the process it serves (procOf):
// port49d's lines read "port49d: ", port49-broker's "port49-broker: ".
func (r *reloader) sayf(format string, args ...any) {
	fmt.Fprintf(stderr, r.procName()+": "+format, args...)
}

func (r *reloader) procName() string {
	if r.proc != "" {
		return r.proc
	}
	return procOf(r.cfg)
}

// combinedFrom is the load that asked loadBoth for a combined try: a SIGHUP,
// which tries both, or the refusal of one source alone.
type combinedFrom int

const (
	atSIGHUP combinedFrom = iota
	fromPolicy
	fromInventory
)

// newReloader is a reloader of the policy in force, live, whose records
// go to log; pass is the in-process broker's Refresh, or nil with none.
func newReloader(cfg config.Config, live *policy.Live, log decision.Emitter,
	pass func(context.Context, []broker.Prior) (broker.RefreshReport, error), m *metrics.Metrics,
	now func() time.Time) *reloader {
	start := now()
	r := &reloader{cfg: cfg, live: live, log: log, pass: pass, metrics: m, now: now,
		interval: cfg.Policy.WatchInterval, priors: []broker.Prior{{Policy: live.Load(), At: start}},
		owed: make(chan bool, 1)}
	// run sets the version the start loaded; this is a test's. In service
	// mode there is no inventory file.
	if cfg.InventoryFile != "" {
		_, r.inventory, _ = inventoryVersion(cfg.InventoryFile)
	}
	r.expiry, _ = live.Load().NextChange(start)
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
	mine := r.live.Load().Source
	if r.docPolicy == mine {
		r.metrics.InventoryPolicyMismatch.Set(0)
		if r.mismatch != "" {
			r.mismatch = ""
			r.sayf("inventory: the service's policy and the policy in force agree again (%s)\n", mine)
		}
		return
	}
	r.metrics.InventoryPolicyMismatch.Set(1)
	if key := r.docPolicy + " " + mine; key != r.mismatch {
		r.mismatch = key
		r.sayf("inventory: the service built bundle %d against policy %s, and the policy in "+
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
			if r.onHUP != nil {
				r.onHUP()
			}
			r.reload(ctx, "SIGHUP")
		case d := <-r.docs:
			r.receive(ctx, d)
		case <-tick.C:
			r.poll(ctx)
		case <-timer.C:
			r.refresh(ctx)
		case now := <-r.owed:
			r.startLeft(now)
		case o := <-r.fullPass:
			r.full(ctx, o)
		}
	}
}

// full runs a full context pass the runner owes (fullPassOwed): every live
// context judged against the policy in force, as a takeover's carry
// judges them, by the whole Refresh, never its token half (whole). A
// replica that minted under another bundle made contexts no pass of this
// one's priors reaches; this one does. A pass that does not complete is
// said and stays owed: the runner asks again at its next look. One that
// completes with nothing else pending tells onSettled, as a settled pass
// does, so the bundle can be recorded as judged once every replica serves
// it.
func (r *reloader) full(ctx context.Context, o fullPassOwed) {
	cur := r.live.Load()
	rep, err := r.whole(ctx, []broker.Prior{{Policy: cur, At: r.now()}})
	if err != nil {
		if ctx.Err() == nil {
			fmt.Fprintf(stderr, "port49-broker: runner: a full context pass owed by %s (bundle %s) stopped "+
				"(%s so far): %v; it stays owed, and runs again at the runner's next look\n", o.who, o.bundle,
				summary(rep), err)
		}
		o.done <- err
		return
	}
	fmt.Fprintf(stderr, "port49-broker: runner: a full context pass owed by %s (bundle %s): %s\n", o.who, o.bundle,
		summary(rep))
	o.done <- nil
	if r.settle.IsZero() && r.retry.IsZero() && r.onSettled != nil {
		r.onSettled(cur)
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
	raw, v, err := policyVersion(r.cfg.Policy.File)
	switch {
	case v == r.live.Load().Source:
		// The file in force ends a run of differing reads: blips days
		// apart — a file missing for a moment in a ConfigMap swap — must
		// not add up to the never-settles alarm.
		alarmed := r.changing >= stillChangingAfter
		r.pending, r.changing = "", 0
		if r.refused != "" || alarmed {
			r.refused = ""
			r.metrics.PolicyFileRefused.Set(0)
			r.sayf("policy: %s %s is the policy in force again (%s, bundle %s)\n", policyKey(r.cfg),
				r.cfg.Policy.File, v, r.live.Load().Bundle)
			r.retryInventory(ctx, "policy file put back")
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
			r.sayf("policy: %s %s has changed at each of the last %d reads, "+
				"%s apart, so it is not loaded; still serving %s (bundle %s); write it once, atomically\n",
				policyKey(r.cfg), r.cfg.Policy.File, stillChangingAfter, r.interval, r.live.Load().Source,
				r.live.Load().Bundle)
		}
	default:
		r.pending = ""
		if r.load(ctx, "file changed", raw, v, err) {
			r.retryInventory(ctx, "file changed")
		}
	}
}

// retryInventory tries again, against the policy now in force, an inventory
// refused against the one before it — the key-group move done in the wrong
// order, or an edit refused together with a policy since fixed or put back
// (plan 6a, C3): inventory_file at the next polls, which read it again; the
// service's document held, now, through loadDocument, which opens it under
// the verify keys in force. A pending inventory edit is loaded by the polls
// as it would be.
func (r *reloader) retryInventory(ctx context.Context, trigger string) {
	r.invRefused = ""
	if l := r.latest; r.cfg.InventoryService != nil && l != nil && l.etag != r.inForce {
		r.docRefused = ""
		r.loadDocument(ctx, trigger, *l)
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
		// Set whatever was said: a retry may have cleared invRefused, and
		// the file in force is refused by nothing.
		r.metrics.InventoryFileRefused.Set(0)
		if r.invRefused != "" || alarmed {
			r.invRefused = ""
			r.sayf("inventory: inventory_file %s is the inventory in force again (bundle %s)\n",
				r.cfg.InventoryFile, r.live.Load().Bundle)
		}
	case v == r.invRefused:
		r.invPending, r.invChanging = "", 0
	case v != r.invPending:
		r.invPending = v
		if r.invChanging++; r.invChanging == stillChangingAfter {
			r.metrics.InventoryFileRefused.Set(1)
			r.sayf("inventory: inventory_file %s has changed at each of the last %d reads, "+
				"%s apart, so it is not loaded; still serving bundle %s; write it once, atomically\n",
				r.cfg.InventoryFile, stillChangingAfter, r.interval, r.live.Load().Bundle)
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
// service sent, and the fetcher is asked to fetch the document again. When
// both sources have a version not in force and the policy parses, the two are
// loaded together, and only together (loadBoth): the operator's SIGHUP
// asserts both edits are done. A policy that does not read or parse is said
// alone, with its own fault, and the inventory is loaded as it would be
// without it.
func (r *reloader) reload(ctx context.Context, trigger string) {
	r.rereadBound()
	r.rereadVerifyKeys()
	r.together = ""
	raw, v, err := policyVersion(r.cfg.Policy.File)
	if err == nil && v != r.live.Load().Source && r.policyParses(raw) {
		if inv, iv, d, ok := r.newInventory(); ok {
			if !r.loadBoth(ctx, trigger, atSIGHUP, raw, v, inv, iv, d) && d != nil {
				r.rejudged = d.etag // the poke below fetches it again (receive)
			}
			if r.cfg.InventoryService != nil {
				select {
				case r.poke <- struct{}{}:
				default:
				}
			}
			return
		}
	}
	r.load(ctx, trigger, raw, v, err)
	if r.cfg.InventoryService != nil {
		if d := r.latest; d != nil && d.etag != r.inForce {
			r.docRefused = ""
			r.loadDocument(ctx, trigger, *d)
			r.rejudged = d.etag // the poke below fetches it again (receive)
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

// settledPolicy is the policy file's version not in force that a combined
// load may take: read now, differing from the policy in force, and agreed by
// the last poll (pending) or refused already — never one the watch has seen
// only once, which an editor may still be writing — and one that parses: a
// policy that does not is its own fault, which no inventory can fix.
func (r *reloader) settledPolicy() ([]byte, string, bool) {
	raw, v, err := policyVersion(r.cfg.Policy.File)
	if err != nil || v == r.live.Load().Source || (v != r.pending && v != r.refused) {
		return nil, "", false
	}
	return raw, v, r.policyParses(raw)
}

// policyParses reports whether raw, the policy file's bytes, compiles against
// the inventory in force: only a policy that does can be refused for what it
// admits, which is the refusal a new inventory can change.
func (r *reloader) policyParses(raw []byte) bool {
	_, err := parseBundle(r.cfg, raw, r.live.Load().Inventory())
	return err == nil
}

// settledInventory is the inventory's version not in force that a combined
// load may take: with inventory_file, the file agreed by the last poll or
// refused already; with the service, the latest document received
// (newInventory).
func (r *reloader) settledInventory() (admission.Inventory, string, *received, bool) {
	if r.cfg.InventoryService == nil {
		if _, v, err := inventoryVersion(r.cfg.InventoryFile); err != nil || (v != r.invPending && v != r.invRefused) {
			return admission.Inventory{}, "", nil, false
		}
	}
	return r.newInventory()
}

// newInventory is the inventory's version not in force, whatever the watch
// has seen of it: with inventory_file, the file read now and parsed; with the
// service, the latest document received, opened now by openDocument — under
// the verify keys in force, never an earlier opening's result (ruling 1). The
// *received it returns carries that opening; it is nil in file mode.
func (r *reloader) newInventory() (admission.Inventory, string, *received, bool) {
	if r.cfg.InventoryService != nil {
		l := r.latest
		if l == nil || l.etag == r.inForce {
			return admission.Inventory{}, "", nil, false
		}
		pub, err := r.openDocument(l.raw)
		if err != nil {
			return admission.Inventory{}, "", nil, false
		}
		return pub.Inv, l.etag, &received{pub: pub, raw: l.raw, etag: l.etag}, true
	}
	raw, v, err := inventoryVersion(r.cfg.InventoryFile)
	if err != nil || v == r.inventory {
		return admission.Inventory{}, "", nil, false
	}
	inv, err := admission.ParseFile(raw, "")
	if err != nil {
		return admission.Inventory{}, "", nil, false
	}
	return inv, v, nil, true
}

// loadBoth builds the bundle from a new policy and a new inventory together
// and puts it in force as one swap when it passes both bounds, judged on the
// combined result (spec §10; plan 6a final review m7): a whole-fleet
// re-address, which each source alone refuses, loads, and no bundle between
// the two revokes a context the final one keeps. Refused, neither is applied,
// and one line names both, once per pair. The source whose load asked for the
// try (from), both at SIGHUP, is marked refused with its alarm up; the other
// is marked only if it was refused already, and one the watch has only seen
// stays pending, to be tried alone at its turn. d is the service's document,
// opened by openDocument just now by the caller, or nil in file mode. It
// reports whether it applied.
func (r *reloader) loadBoth(ctx context.Context, trigger string, from combinedFrom, raw []byte, v string,
	inv admission.Inventory, iv string, d *received) bool {
	old := r.live.Load()
	fix := "fix the file"
	if d != nil {
		fix = "fix the source of truth"
	}
	pol, err := parseBundle(r.cfg, raw, inv)
	if err == nil {
		err = bundle.CheckFrom(old, pol, r.cfg.MaxRemovedPercent, fix)
	}
	if err == nil {
		// The policy's bound judges the policy's effect alone: base is the
		// policy in force over the new inventory, so a device the inventory
		// takes out is Check's, quarantined as decision 20 says, and the
		// line blames the policy file only for what the policy does. A base
		// that does not parse leaves every device the policy's (nil).
		base, berr := bundle.Parse(old.Raw(), inv, policyEnv(r.cfg))
		if berr != nil {
			base = nil
		}
		if err = bundle.CheckAdmissionOver(old, base, pol, r.cfg.MaxRemovedPercent, r.now()); err != nil {
			err = fmt.Errorf("%s %s: %w", policyKey(r.cfg), r.cfg.Policy.File, err)
		} else if err = mfaRefusal(base, pol); err != nil {
			err = fmt.Errorf("%s %s: %w", policyKey(r.cfg), r.cfg.Policy.File, err)
		}
	}
	if err != nil {
		if from != fromInventory || v == r.refused {
			r.metrics.PolicyReloads.WithLabelValues("refused").Inc()
			r.metrics.PolicyFileRefused.Set(1)
			r.refused, r.pending = v, ""
		}
		// A service document not in force was tried alone when it arrived.
		if d != nil || from != fromPolicy || iv == r.invRefused {
			r.metrics.InventoryReloads.WithLabelValues("refused").Inc()
			if d != nil {
				r.docRefused = iv
				r.metrics.InventoryBundleRefused.Set(1)
			} else {
				r.invRefused, r.invPending = iv, ""
				r.metrics.InventoryFileRefused.Set(1)
			}
		}
		if pair := v + " " + iv; pair != r.together {
			r.together = pair
			r.sayf("policy and inventory reload (%s) refused together; still serving %s "+
				"(bundle %s): %s\n", trigger, old.Source, old.Bundle,
				refusalLine(r.procName(), err, d == nil, old, pol))
		}
		return false
	}
	r.refused, r.changing, r.pending, r.together = "", 0, "", ""
	r.metrics.PolicyFileRefused.Set(0)
	r.metrics.PolicyReloads.WithLabelValues("applied").Inc()
	r.metrics.InventoryReloads.WithLabelValues("applied").Inc()
	if d != nil {
		if d.pub.Doc.Sequence < r.seq {
			r.sayf("inventory: the service's sequence went back from %d to %d: its state_dir "+
				"was reset; applying it (spec §10)\n", r.seq, d.pub.Doc.Sequence)
		}
		r.inForce, r.seq, r.inForceAt, r.latestRaw = d.etag, d.pub.Doc.Sequence, d.pub.Doc.PublishedAt, d.raw
		r.docRefused, r.docPolicy, r.latestAhead = "", d.pub.Doc.PolicySHA256, false
		r.metrics.InventoryBundleRefused.Set(0)
		r.metrics.InventoryBundleSequence.Set(float64(r.seq))
		r.persist(d.raw)
	} else {
		r.inventory, r.invRefused, r.invPending, r.invChanging = iv, "", "", 0
		r.metrics.InventoryFileRefused.Set(0)
	}
	r.invSeen.Store(r.now().UnixNano())
	now := r.swap(pol)
	rep := bundle.Diff(old, pol, now)
	r.sayf("policy and inventory reloaded together (%s): %s replaces %s; %s; %d device(s) "+
		"quarantined now, %d before; %d refused admission\n", trigger, pol.Source, old.Source, rep.Summary(),
		quarantinedAt(pol, now), quarantinedAt(old, now), len(pol.AdmissionRefusals()))
	r.after(ctx, "policy and inventory", rep, pol, now)
	r.sayPolicyMatch()
	return true
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
		r.sayf("SIGHUP: inventory.max_removed_percent not re-read from %s (%s); keeping %d%%\n",
			r.cfgPath, oneLine(err), r.cfg.MaxRemovedPercent)
	case n != r.cfg.MaxRemovedPercent:
		r.sayf("SIGHUP: inventory.max_removed_percent is now %d%% (was %d%%)\n", n,
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
//
// An unchanged answer is counted here, not by the fetcher: "unchanged" when
// it confirms the document in force, and "refused" when it confirms one
// port49d refused, which is not the healthy fetch "unchanged" reads as
// beside port49_inventory_bundle_refused at 1 (final review Minor 5).
//
// The fetch a SIGHUP asks for brings back, whole, the document that SIGHUP
// has just judged (reload): refused again under the same keys and bound, it
// is held and neither judged, said nor counted a second time (final review
// Minor 6).
func (r *reloader) receive(ctx context.Context, d received) {
	rejudged := r.rejudged
	if !d.unchanged {
		r.rejudged = ""
	}
	if d.unchanged {
		outcome := "unchanged"
		if d.etag != r.inForce {
			outcome = "refused"
		}
		r.metrics.InventoryFetches.WithLabelValues(outcome).Inc()
	}
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
	if d.etag == rejudged && d.etag == r.docRefused {
		return
	}
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
				r.sayf("inventory: bundle %d, in force, no longer opens under the verify keys "+
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
	old := r.live.Load()
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
	opened := err == nil
	if err == nil {
		pol, err = bundle.Parse(old.Raw(), pub.Inv, policyEnv(r.cfg))
	}
	if err == nil {
		err = bundle.CheckFrom(old, pol, r.cfg.MaxRemovedPercent, "fix the source of truth")
	}
	if err != nil && opened {
		// Opened and judged just now, but refused against the policy in
		// force: tried with the policy's settled version not in force, if
		// there is one (spec §10).
		if praw, pv, ok := r.settledPolicy(); ok {
			r.loadBoth(ctx, trigger, fromInventory, praw, pv, pub.Inv, d.etag, &received{pub: pub, raw: d.raw, etag: d.etag})
			return
		}
	}
	if err != nil {
		if !stillAhead {
			r.metrics.InventoryReloads.WithLabelValues("refused").Inc()
		}
		r.metrics.InventoryBundleRefused.Set(1)
		if d.etag != r.docRefused {
			r.docRefused = d.etag
			r.sayf("inventory reload (%s) refused; still serving bundle %s (%d): %s\n", label,
				old.Bundle, r.seq, oneLine(quotesCut{err}))
		}
		return
	}
	r.docRefused = ""
	r.metrics.InventoryBundleRefused.Set(0)
	if pub.Doc.Sequence < r.seq {
		r.sayf("inventory: the service's sequence went back from %d to %d: its state_dir was "+
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
	r.sayf("inventory reloaded (%s): %s; %d device(s) quarantined now, %d before; %d refused "+
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
			r.sayf("inventory: state_dir %s: %s; a restart with the service down would start "+
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
			r.sayf("SIGHUP: %s has an inventory.service block; the inventory source is read at "+
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
		r.sayf("SIGHUP: inventory.service.verify_key_files not re-read from %s (%s); keeping "+
			"the keys in force\n", r.cfgPath, oneLine(err))
	case svc == nil:
		r.sayf("SIGHUP: %s has no inventory.service block; the inventory source is read at "+
			"start only; keeping the service and the keys in force\n", r.cfgPath)
	default:
		r.verifyKeys.Store(&keys)
		r.sayf("SIGHUP: %d inventory verify key(s) in force\n", len(keys))
		if cur := r.cfg.InventoryService; svc.URL != cur.URL || svc.CAFile != cur.CAFile ||
			svc.TLSCertFile != cur.TLSCertFile || svc.TLSKeyFile != cur.TLSKeyFile || svc.StateDir != cur.StateDir ||
			svc.MirrorDir != cur.MirrorDir || svc.PollInterval != cur.PollInterval {
			r.sayf("SIGHUP: inventory.service in %s differs from the one in force beyond "+
				"verify_key_files; those keys are read at start only, so still asking %s every %s\n", r.cfgPath,
				cur.URL, cur.PollInterval)
		}
	}
}

// mfaRefusal refuses a policy edit that introduces a device whose per_login_mfa
// levels accept no common method (decision 45 ruling 11): an entry base, the
// policy in force over the same inventory, does not already have. One already
// in force freezes no edit, so a grant revocation loads at 3am while a device
// is quarantined over it; an inventory reload or a start quarantines instead,
// so an inventory sync never freezes the fleet's inventory. A nil base counts
// every entry.
func mfaRefusal(base, pol *policy.Policy) error {
	fresh := policy.NewMFADisjoint(base, pol)
	if len(fresh) == 0 {
		return nil
	}
	q, e := fresh[0], fresh[0].Entries[0]
	return fmt.Errorf("per_login_mfa: %s would be quarantined: %s; %d device(s) in all (spec §5.1.5)", q.Device, e.Cause,
		len(fresh))
}

// load puts raw, the policy file's content read as version v, in force and
// refreshes, if it loads and passes the admission bound. A file that does
// not, or could not be read (err), changes nothing.
func (r *reloader) load(ctx context.Context, trigger string, raw []byte, v string, err error) bool {
	r.changing = 0
	old := r.live.Load()
	var pol *policy.Policy
	forAdmission := false
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
			if err = bundle.CheckAdmission(old, pol, r.cfg.MaxRemovedPercent, r.now()); err != nil {
				forAdmission = true
				err = fmt.Errorf("%s %s: %w", policyKey(r.cfg), r.cfg.Policy.File, err)
			} else if err = mfaRefusal(old, pol); err != nil {
				// Not forAdmission: no inventory settles levels that accept no
				// common method, so it is its own fault, said alone.
				err = fmt.Errorf("%s %s: %w", policyKey(r.cfg), r.cfg.Policy.File, err)
			}
		}
	} else {
		err = fmt.Errorf("%s %s: %w", policyKey(r.cfg), r.cfg.Policy.File, err)
	}
	if err != nil {
		// Refused alone for what it admits, it is tried with the inventory's
		// settled version not in force, if there is one (spec §10). One that
		// did not read or parse is its own fault, said alone: no inventory
		// can fix it, and a pending inventory edit is not held up by it.
		if forAdmission {
			if inv, iv, d, ok := r.settledInventory(); ok {
				return r.loadBoth(ctx, trigger, fromPolicy, raw, v, inv, iv, d)
			}
		}
		r.metrics.PolicyReloads.WithLabelValues("refused").Inc()
		r.metrics.PolicyFileRefused.Set(1)
		r.refused = v
		r.sayf("policy reload (%s) refused; still serving %s (bundle %s): %s\n", trigger,
			old.Source, old.Bundle, refusalLine(r.procName(), err, false, old, pol))
		return false
	}
	r.refused = ""
	r.metrics.PolicyFileRefused.Set(0)
	if pol.Source == old.Source {
		r.metrics.PolicyReloads.WithLabelValues("unchanged").Inc()
		r.sayf("policy reload (%s): %s unchanged, %s in force (bundle %s)\n",
			trigger, policyKey(r.cfg), pol.Source, pol.Bundle)
		return false
	}
	r.metrics.PolicyReloads.WithLabelValues("applied").Inc()
	now := r.swap(pol)
	// An inventory edit refused against the policy replaced — the key-group
	// move done in the wrong order, say — is tried again against this one at
	// the next polls (plan 6a, C3).
	r.invRefused = ""
	r.sayf("policy reloaded (%s): %s replaces %s (bundle %s); %d device(s) quarantined now, %d before\n",
		trigger, pol.Source, old.Source, pol.Bundle, quarantinedAt(pol, now), quarantinedAt(old, now))
	r.after(ctx, "policy", bundle.Diff(old, pol, now), pol, now)
	r.sayPolicyMatch()
	return true
}

// loadInventory builds a bundle from raw, the inventory file read as version
// v, and the policy in force, and puts it in force if it loads and passes the
// bounded-change check (spec §10). One that does not changes nothing: the
// bundle in force keeps serving, the refusal is said once per version, and
// port49_inventory_file_refused is 1 until a file loads or the one in force
// is put back.
func (r *reloader) loadInventory(ctx context.Context, trigger string, raw []byte, v string, err error) {
	r.invChanging = 0
	old := r.live.Load()
	var pol *policy.Policy
	var inv admission.Inventory
	if err == nil {
		inv, err = admission.ParseFile(raw, "") // the error below names the file
		if err != nil {
			err = fmt.Errorf("inventory_file %s: %w", r.cfg.InventoryFile, quotesCut{err})
		} else if pol, err = r.inventoryBundle(old, inv); err != nil {
			// Refused alone, a file that parses is tried with the policy's
			// settled version not in force, if there is one (spec §10).
			if praw, pv, ok := r.settledPolicy(); ok {
				r.loadBoth(ctx, trigger, fromInventory, praw, pv, inv, v, nil)
				return
			}
		}
	} else {
		err = fmt.Errorf("inventory_file %s: %w", r.cfg.InventoryFile, err)
	}
	if err != nil {
		r.metrics.InventoryReloads.WithLabelValues("refused").Inc()
		r.metrics.InventoryFileRefused.Set(1)
		r.invRefused = v
		r.sayf("inventory reload (%s) refused; still serving bundle %s: %s\n", trigger,
			old.Bundle, oneLine(err))
		return
	}
	r.inventory, r.invRefused = v, ""
	r.invSeen.Store(r.now().UnixNano())
	r.metrics.InventoryFileRefused.Set(0)
	if pol.Bundle == old.Bundle {
		// The same devices, respelled: nothing to swap.
		r.metrics.InventoryReloads.WithLabelValues("unchanged").Inc()
		r.sayf("inventory reload (%s): the same inventory, respelled; bundle %s in force\n",
			trigger, old.Bundle)
		return
	}
	r.metrics.InventoryReloads.WithLabelValues("applied").Inc()
	now := r.swap(pol)
	// A policy edit refused against the inventory replaced is tried again
	// against this one at the next polls, as the other way round (C3).
	r.refused = ""
	rep := bundle.Diff(old, pol, now)
	r.sayf("inventory reloaded (%s): %s; %d device(s) quarantined now, %d before; %d refused "+
		"admission\n", trigger, rep.Summary(), quarantinedAt(pol, now), quarantinedAt(old, now),
		len(pol.AdmissionRefusals()))
	r.after(ctx, "inventory", rep, pol, now)
}

// inventoryBundle is the bundle inv, the inventory file parsed, makes with
// the policy in force, if it passes Check. A fault is named as the
// inventory's, not the policy file's: the policy in force loaded before (plan
// 6a, M5).
func (r *reloader) inventoryBundle(old *policy.Policy, inv admission.Inventory) (*policy.Policy, error) {
	pol, err := bundle.Parse(old.Raw(), inv, policyEnv(r.cfg))
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
// expiry is read from pol, a settle pass is owed, and onSwap is told.
func (r *reloader) swap(pol *policy.Policy) time.Time {
	if r.beforeSwap != nil {
		r.beforeSwap(pol)
	}
	r.live.Swap(pol)
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
	if r.pass == nil {
		// No refresh pass reads the priors: keep only the policy in force,
		// or every one ever loaded stays in memory (task 14 review I-1).
		r.priors = []broker.Prior{{Policy: pol, At: now}}
	} else {
		r.priors[len(r.priors)-1].Until = now
		r.priors = append(r.priors, broker.Prior{Policy: pol, At: now})
	}
	r.expiry, _ = pol.NextChange(now)
	r.settle = now.Add(settleAfter(r.interval))
	if r.pass != nil {
		r.metrics.PolicyRefreshPending.Set(1)
	}
	if r.onSwap != nil {
		r.onSwap(pol)
	}
	return now
}

// after is what every swap runs once its line is written: an inventory_change
// record for each security change it made, the lines a start would print, and
// the refresh that carries the bundle into live contexts. file, "policy" or
// "inventory", names the file whose swap it was: the security line's prefix
// says which file changed access.
func (r *reloader) after(ctx context.Context, file string, rep bundle.Report, pol *policy.Policy, now time.Time) {
	if n := r.securityEvents(rep, now); n > 0 {
		r.sayf("%s: %d security change(s) written as inventory_change records "+
			"(spec §10)\n", file, n)
	}
	sayPolicy(r.procName(), pol, now)
	r.refresh(ctx)
	// After the pass, not before: the walk over every subject and device must
	// not delay the supersede that a tightened requirement depends on.
	if r.mfaUnavailable != nil {
		if line := r.mfaUnavailable(pol, now); line != "" {
			r.sayf("broker: %s\n", line)
		}
	}
}

// securityEvents writes one inventory_change record for each security change
// the swap made, and counts it (spec §5.7, §10). It returns how many.
func (r *reloader) securityEvents(rep bundle.Report, now time.Time) int {
	changes := rep.Security()
	for _, c := range changes {
		r.log.Emit(decision.Record{TS: now, Event: decision.EventInventoryChange,
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
// pass settleAfter after a pass that crossed an expiry.
//
// A complete pass resets the priors to the policy in force only once no
// settle pass is owed. While one is, the priors stay, the newest's span
// closed at the pass's instant, so the settle pass judges again every
// token minted under each of them since: another replica that reloads
// late mints under a replaced policy after the first pass (plan 7e,
// Ruling 8).
//
// port49_policy_refresh_pending is 1 from a swap or an expiry until the settle
// pass after it completes, and while a pass is owed a retry: while it is, a
// live context may still hold a policy no longer in force — a withdrawn or
// expired grant included. A complete pass that leaves it at 0 tells
// onSettled, when set, the policy in force.
func (r *reloader) refresh(ctx context.Context) {
	if r.pass == nil {
		// No broker in the process: nothing to carry, and nothing scheduled,
		// or an expiry already past would fire the timer again at once.
		r.expiry, r.settle, r.retry, r.due = time.Time{}, time.Time{}, time.Time{}, time.Time{}
		return
	}
	if !r.expiry.IsZero() && !r.now().Before(r.expiry) {
		// A grant has expired, and until this pass reaches every context
		// one may still hold it.
		r.metrics.PolicyRefreshPending.Set(1)
	}
	rep, err := r.pass(ctx, r.priors)
	if err != nil && ctx.Err() != nil {
		return // port49d is shutting down: there is no retry to announce
	}
	if err != nil {
		r.stopped = true
		r.metrics.PolicyRefreshPending.Set(1)
		if errors.Is(err, store.ErrConflict) {
			// Every context was visited and the store answered: only the busy
			// ones, counted failed, are left.
			r.sayf("policy refresh: %d context(s) still changing after every attempt keep "+
				"their previous policy (%s); trying them again in %s\n", rep.Failed, summary(rep), refreshRetry)
		} else {
			r.sayf("policy refresh stopped (%s so far): %v; the contexts not reached keep "+
				"their previous policy; trying again in %s\n", summary(rep), err, refreshRetry)
		}
		r.retry = r.now().Add(refreshRetry)
		r.reschedule()
		return
	}
	cur := r.live.Load()
	r.retry = time.Time{}
	if !r.settle.IsZero() && !rep.At.Before(r.settle) {
		r.settle = time.Time{}
	}
	if !r.expiry.IsZero() && !rep.At.Before(r.expiry) {
		r.settle = rep.At.Add(settleAfter(r.interval))
	}
	r.expiry, _ = cur.NextChange(rep.At)
	if r.settle.IsZero() {
		r.priors = []broker.Prior{{Policy: cur, At: rep.At}}
		r.metrics.PolicyRefreshPending.Set(0)
	} else {
		r.priors[len(r.priors)-1].Until = rep.At
		r.metrics.PolicyRefreshPending.Set(1)
	}
	switch {
	case r.stopped:
		r.stopped = false
		r.sayf("policy refresh finished: %s\n", summary(rep))
	case rep.Updated+rep.Revoked+rep.Quarantined+rep.Failed+rep.TokenKeys > 0:
		r.sayf("policy refresh: %s\n", summary(rep))
	}
	r.reschedule()
	if r.settle.IsZero() && r.onSettled != nil {
		r.onSettled(cur)
	}
}

// startLeft is what a start on a persistent store left unjudged (plan
// 7d; decision 35, a start on etcd, step 6): a pass is owed, at once for
// a context still changing (Ruling T12-d), at the next retry for one
// under an unheld key, which every path denies meanwhile (T12-a). Until
// one completes, port49_policy_refresh_pending is 1 (re-review r-m1).
func (r *reloader) startLeft(now bool) {
	r.metrics.PolicyRefreshPending.Set(1)
	r.stopped = true
	r.retry = r.now()
	if !now {
		r.retry = r.retry.Add(refreshRetry)
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

// refusalLine is a refused reload's error on one line for stderr, a log:
// every quoted value a rule of any of pols marks secret is redacted first,
// as sayPolicy redacts a quarantine's cause, then each is cut to maxQuoted
// (quotesCut), so a cut never leaves a secret's head (spec §5.8;
// pre-flight I3). The guard's causes quote policy text, so the policy in
// force and the refused one are both given; a nil one (a file that did not
// parse) is skipped. A refusal for the bound (bundle.OverBound) ends with
// unguardedAtStart, of both files when both are files on disk, as proc's
// start would treat them; on port49-broker its remedy names
// port49-broker.yaml (Task 15a review M-3).
func refusalLine(proc string, err error, both bool, pols ...*policy.Policy) string {
	line := redactedLine(err, pols)
	if proc == "port49-broker" {
		line = brokerWording(line)
	}
	if over := (*bundle.OverBound)(nil); errors.As(err, &over) {
		if proc == "port49-broker" {
			if both {
				return line + brokerUnguardedAtStartBoth
			}
			return line + brokerUnguardedAtStart
		}
		if both {
			return line + unguardedAtStartBoth
		}
		line += unguardedAtStart
	}
	return line
}

// redactedLine is refusalLine's line before any process's wording: err
// redacted with every rule of pols marks secret, on one line, each quoted
// value cut.
func redactedLine(err error, pols []*policy.Policy) string {
	line := err.Error()
	for _, p := range pols {
		if p != nil {
			line = platform.RedactQuoted(p.Redactions(), line)
		}
	}
	return oneLine(quotesCut{errors.New(line)})
}

// brokerWording puts the advice of a guard refusal in port49-broker's
// terms (Task 18; Task 15a carry): its config is port49-broker.yaml, whose
// inventory.max_removed_percent a SIGHUP re-reads as port49d's does, and it
// serves no device, so a fleet is taken off by stopping every port49d, not
// by stopping it. The words are bundle's own, replaced by their text.
func brokerWording(line string) string {
	for _, r := range [][2]string{
		{bundle.RaiseBound, strings.ReplaceAll(bundle.RaiseBound, "port49d.yaml", "port49-broker.yaml")},
		{bundle.KeyRefsFile, strings.ReplaceAll(bundle.KeyRefsFile, "port49d.yaml", "port49-broker.yaml")},
		{bundle.StopFleet, "to take the whole fleet off deliberately, stop every port49d (port49-broker serves no device)"},
	} {
		line = strings.ReplaceAll(line, r[0], r[1])
	}
	return line
}

// brokerStartWording is brokerWording for a refusal at port49-broker's
// start, held in passGuardAtStart before anything is served: a SIGHUP is
// read only once the start has passed, so the raised bound is read by a
// restart.
func brokerStartWording(line string) string {
	return strings.ReplaceAll(brokerWording(line),
		strings.ReplaceAll(bundle.RaiseBound, "port49d.yaml", "port49-broker.yaml"),
		"raise inventory.max_removed_percent in port49-broker.yaml and restart port49-broker, which reads it at its "+
			"start (a SIGHUP is not read until the start has passed)")
}

// unguardedAtStart ends the line of a reload the guard refused (pre-flight
// I4): the refused file stays on disk, and a start has no policy in force to
// bound against, so a pod rescheduled, a crash or the next deploy would
// load it and take the devices out of service the guard just kept in.
const unguardedAtStart = "; the refused file is still on disk and is NOT what is serving: a restart of port49d " +
	"would load it with no such bound, so revert or fix it now"

// unguardedAtStartBoth is unguardedAtStart for a combined reload in file
// mode, which refuses the policy file and the inventory file together.
const unguardedAtStartBoth = "; the refused files are still on disk and are NOT what is serving: a restart of " +
	"port49d would load them with no such bound, so revert or fix them now"

// brokerUnguardedAtStart is unguardedAtStart on port49-broker, whose start
// the reload guard holds not ready against the bundle last judged (Ruling
// 17): a rollout onto the refused file takes every replica it reaches out
// of minting, and only with no policy in meta/judged is it loaded unbounded.
const brokerUnguardedAtStart = "; the refused file is still on disk and is NOT what is serving: a restart of " +
	"port49-broker holds that replica not ready against the bundle last judged (and loads it unbounded when " +
	"meta/judged has no policy), so a rollout onto it serves no mints: revert or fix it now"

// brokerUnguardedAtStartBoth is brokerUnguardedAtStart for both files.
const brokerUnguardedAtStartBoth = "; the refused files are still on disk and are NOT what is serving: a restart " +
	"of port49-broker holds that replica not ready against the bundle last judged (and loads them unbounded when " +
	"meta/judged has no policy), so a rollout onto them serves no mints: revert or fix them now"

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
