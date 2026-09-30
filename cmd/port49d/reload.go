package main

import (
	"context"
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
	"github.com/rhwendt/port49/internal/engine"
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
	// invSeen is when the inventory file was last read and found in force,
	// or loaded: port49_inventory_snapshot_age_seconds reads it at scrape.
	invSeen atomic.Int64
	// stopped is set while the last refresh pass did not complete, so the
	// one that does says so whatever it found.
	stopped bool
}

func newReloader(cfg config.Config, b *broker.Broker, m *metrics.Metrics, now func() time.Time) *reloader {
	start := now()
	r := &reloader{cfg: cfg, broker: b, metrics: m, now: now, interval: cfg.Broker.PolicyWatchInterval,
		priors: []broker.Prior{{Policy: b.Policy.Load(), At: start}}}
	// run sets the version the start loaded; this is a test's.
	_, r.inventory, _ = inventoryVersion(cfg.InventoryFile)
	r.expiry, _ = b.Policy.Load().NextChange(start)
	r.reschedule()
	r.invSeen.Store(start.UnixNano())
	m.WatchInventoryAge(func() float64 { return now().Sub(time.Unix(0, r.invSeen.Load())).Seconds() })
	return r
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

// poll reads both files, the policy first.
func (r *reloader) poll(ctx context.Context) {
	r.pollPolicy(ctx)
	r.pollInventory(ctx)
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
// second read, because the operator asked. It re-reads the bound first, so
// raising it and sending SIGHUP applies a change refused over it, and it
// loads the inventory whenever its version is not the one in force, so a
// refused inventory is tried again.
func (r *reloader) reload(ctx context.Context, trigger string) {
	r.rereadBound()
	raw, v, err := policyVersion(r.cfg.Broker.PolicyFile)
	r.load(ctx, trigger, raw, v, err)
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
	raw, err := os.ReadFile(r.cfgPath)
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
	r.after(ctx, bundle.Diff(old, pol, now), pol, now)
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
	r.after(ctx, rep, pol, now)
}

// inventoryBundle is the bundle raw, the inventory file's bytes, makes with
// the policy in force, if it parses and passes Check. A fault after the parse
// is named as the inventory's, not the policy file's: the policy in force
// loaded before (plan 6a, M5).
func (r *reloader) inventoryBundle(old *policy.Policy, raw []byte) (*policy.Policy, error) {
	inv, err := admission.ParseFile(raw, r.cfg.InventoryFile)
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
	now := r.now()
	r.priors[len(r.priors)-1].Until = now
	r.priors = append(r.priors, broker.Prior{Policy: pol, At: now})
	r.expiry, _ = pol.NextChange(now)
	r.settle = now.Add(settleAfterReload)
	r.metrics.PolicyRefreshPending.Set(1)
	return now
}

// after is what every swap runs once its line is written: the lines a start
// would print, and the refresh that carries the bundle into live contexts.
func (r *reloader) after(ctx context.Context, rep bundle.Report, pol *policy.Policy, now time.Time) {
	sayPolicy(pol, now)
	r.refresh(ctx)
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
