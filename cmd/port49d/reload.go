package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/broker"
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

// reloader keeps the broker's policy the one in broker.policy_file (plan 4b).
// It is one goroutine, so a reload, a poll and a scheduled refresh never run
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
// is owed a retry.
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
	// inventory is the inventory file's version as loaded at start, and
	// inventorySaid the changed version last said.
	inventory, inventorySaid string
	// stopped is set while the last refresh pass did not complete, so the
	// one that does says so whatever it found.
	stopped bool
}

func newReloader(cfg config.Config, b *broker.Broker, m *metrics.Metrics, now func() time.Time) *reloader {
	start := now()
	r := &reloader{cfg: cfg, broker: b, metrics: m, now: now, interval: cfg.Broker.PolicyWatchInterval,
		priors: []broker.Prior{{Policy: b.Policy.Load(), At: start}}}
	_, r.inventory, _ = fileVersion(cfg.InventoryFile)
	r.expiry, _ = b.Policy.Load().NextChange(start)
	r.reschedule()
	return r
}

// fileVersion is a file's content and a string that changes when it does: its
// sha256, or why it could not be read.
func fileVersion(path string) ([]byte, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "unreadable: " + err.Error(), err
	}
	return raw, engine.HashOf(raw), nil
}

// policyVersion is fileVersion for the policy file, read as the start reads it
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

// poll reads the policy file and loads it once two reads in a row agree on a
// version that is neither the one in force nor one already refused. What it
// loads is the second read's bytes, the ones the two reads agreed on: read
// again, a file an editor began writing in between would be loaded half-way.
func (r *reloader) poll(ctx context.Context) {
	raw, v, err := policyVersion(r.cfg.Broker.PolicyFile)
	switch {
	case v == r.broker.Policy.Load().Bundle:
		// The file in force ends a run of differing reads: blips days
		// apart — a file missing for a moment in a ConfigMap swap — must
		// not add up to the never-settles alarm.
		alarmed := r.changing >= stillChangingAfter
		r.pending, r.changing = "", 0
		if r.refused != "" || alarmed {
			r.refused = ""
			r.metrics.PolicyFileRefused.Set(0)
			fmt.Fprintf(stderr, "port49d: policy: broker.policy_file %s is the policy in force again (%s)\n",
				r.cfg.Broker.PolicyFile, v)
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
				"%s apart, so it is not loaded; still serving %s; write it once, atomically\n",
				r.cfg.Broker.PolicyFile, stillChangingAfter, r.interval, r.broker.Policy.Load().Bundle)
		}
	default:
		r.pending = ""
		r.load(ctx, "file changed", raw, v, err)
	}
}

// reload reads the policy file once and loads what it read: SIGHUP's path,
// with no second read, because the operator asked.
func (r *reloader) reload(ctx context.Context, trigger string) {
	raw, v, err := policyVersion(r.cfg.Broker.PolicyFile)
	r.load(ctx, trigger, raw, v, err)
}

// load puts raw, the policy file's content read as version v, in force and
// refreshes, if it loads. A file that does not load, or could not be read
// (err), changes nothing.
func (r *reloader) load(ctx context.Context, trigger string, raw []byte, v string, err error) {
	r.checkInventory()
	r.changing = 0
	old := r.broker.Policy.Load()
	var pol *policy.Policy
	if err == nil && v == old.Bundle {
		// The bytes in force: nothing to compile, and nothing is refused
		// that was loaded before (a SIGHUP with no edit).
		pol = old
	} else if err == nil {
		pol, err = parsePolicy(r.cfg, raw)
	} else {
		err = fmt.Errorf("broker.policy_file %s: %w", r.cfg.Broker.PolicyFile, err)
	}
	if err != nil {
		r.metrics.PolicyReloads.WithLabelValues("refused").Inc()
		r.metrics.PolicyFileRefused.Set(1)
		r.refused = v
		fmt.Fprintf(stderr, "port49d: policy reload (%s) refused; still serving %s: %s\n", trigger, old.Bundle,
			oneLine(err))
		return
	}
	r.refused = ""
	r.metrics.PolicyFileRefused.Set(0)
	if pol.Bundle == old.Bundle {
		r.metrics.PolicyReloads.WithLabelValues("unchanged").Inc()
		fmt.Fprintf(stderr, "port49d: policy reload (%s): broker.policy_file unchanged, %s in force\n", trigger,
			pol.Bundle)
		return
	}
	r.broker.Policy.Swap(pol)
	// Swap waits for the mints in flight, which finish on the policy they
	// started with, so the replaced policy's span ends when it returns.
	now := r.now()
	r.priors[len(r.priors)-1].Until = now
	r.priors = append(r.priors, broker.Prior{Policy: pol, At: now})
	r.expiry, _ = pol.NextChange(now)
	r.settle = now.Add(settleAfterReload)
	r.metrics.PolicyRefreshPending.Set(1)
	r.metrics.PolicyReloads.WithLabelValues("applied").Inc()
	fmt.Fprintf(stderr, "port49d: policy reloaded (%s): %s replaces %s; %d device(s) quarantined now, %d before\n",
		trigger, pol.Bundle, old.Bundle, quarantinedAt(pol, now), quarantinedAt(old, now))
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

// checkInventory says, once per change, that the inventory file on disk is
// not the one port49d loaded. The inventory is read at start and only then
// until plan 6's snapshot refresh (spec §10): admission, the key ring and the
// broker's device table are built from it once, and a reload checks the new
// policy against that same inventory. So an inventory edit is not applied by a
// reload, and an operator who sent SIGHUP after one is told so rather than
// left to believe it.
func (r *reloader) checkInventory() {
	_, v, _ := fileVersion(r.cfg.InventoryFile)
	if v == r.inventory || v == r.inventorySaid {
		return
	}
	r.inventorySaid = v
	fmt.Fprintf(stderr, "port49d: inventory_file %s has changed since start and is not reloaded (plan 6); the "+
		"policy is checked against the inventory loaded at start; restart port49d to apply it\n", r.cfg.InventoryFile)
}
