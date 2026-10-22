package port49d

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
)

// failClosedDevices is how many devices a fail-closed finding's line names.
const failClosedDevices = 3

// sayFailClosed says which compositions of pol answer fail-closed (spec §12,
// "Projection reports"): each projection_refused and projection_overflow
// finding at now and at every later grant expiry, worded as `policy test`
// words it with the device count and the first failClosedDevices, then
// sets port49_policy_fail_closed_compositions to how many hold now. It is
// said at start, on the start's goroutine; after a swap's refresh pass and
// at each grant expiry the reloader's failClosedReporter says it.
func sayFailClosed(proc string, pol *policy.Policy, now time.Time, m *metrics.Metrics) {
	if m == nil || pol == nil {
		return
	}
	reportFailClosed(stderr, proc, pol, pol.FailClosedCompositions(now), m)
}

// reportFailClosed writes found, pol's fail-closed compositions, to w and
// sets the gauge. The count line comes first and is said when the count is
// above 0 or was before, so a fix is said as a fault is. The finding quotes
// the policy's own text, and stderr is a log: it is redacted as sayPolicy
// redacts (spec §5.8).
func reportFailClosed(w io.Writer, proc string, pol *policy.Policy, found []policy.FailClosed, m *metrics.Metrics) {
	n := 0
	for _, f := range found {
		if !f.Later {
			n++
		}
	}
	before := m.SetPolicyFailClosed(n)
	redact := pol.Redactions()
	say := func(format string, args ...any) {
		fmt.Fprintln(w, platform.RedactQuoted(redact, proc+": "+fmt.Sprintf(format, args...)))
	}
	if n > 0 || before > 0 {
		say("policy: %d composition(s) answered fail-closed now (port49 policy test names them)", n)
	}
	for _, f := range found {
		say("policy: %s: %s; %s", f.Kind, f.Message, deviceList(f.Devices))
	}
}

// failClosedReporter says the fail-closed compositions of each generation
// the reloader asks for, off the reload goroutine: the walk over every
// subject and device must not delay a reload, a refresh pass or the
// timer at an expiry. One worker at a time works a report out, and only
// the latest generation asked for: one still pending when a newer is asked
// for is dropped, and one finished after a newer was asked for is not said,
// so an older report never overwrites a newer. The worker runs only while
// there is a report to work out, and close stops it.
type failClosedReporter struct {
	m *metrics.Metrics
	// compute works a report out: FailClosedCompositions, which a test
	// holds.
	compute func(pol *policy.Policy, now time.Time) []policy.FailClosed

	mu   sync.Mutex
	idle *sync.Cond // told when the worker exits
	// gen is the latest generation asked for, next the one waiting for the
	// worker, nil when none; running is whether the worker is up.
	gen     uint64
	next    *failClosedJob
	running bool
	closed  bool
}

// failClosedJob is one generation's report: the policy put in force, the
// instant its refresh pass judged at, and where its lines go.
type failClosedJob struct {
	gen  uint64
	w    io.Writer
	proc string
	pol  *policy.Policy
	now  time.Time
}

func newFailClosedReporter(m *metrics.Metrics) *failClosedReporter {
	f := &failClosedReporter{m: m, compute: (*policy.Policy).FailClosedCompositions}
	f.idle = sync.NewCond(&f.mu)
	return f
}

// ask has the report on pol at now said to w, once the worker reaches it,
// superseding any generation asked for before. It never waits. The
// reloader asks after the refresh pass of the generation, so the report
// follows it.
func (f *failClosedReporter) ask(w io.Writer, proc string, pol *policy.Policy, now time.Time) {
	if f == nil || f.m == nil || pol == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	f.gen++
	f.next = &failClosedJob{gen: f.gen, w: w, proc: proc, pol: pol, now: now}
	if !f.running {
		f.running = true
		go f.work()
	}
}

// work works out each pending report until none is left. A report is said
// under the lock, and only if no newer one was asked for meanwhile.
func (f *failClosedReporter) work() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for f.next != nil && !f.closed {
		j := f.next
		f.next = nil
		f.mu.Unlock()
		found := f.compute(j.pol, j.now)
		f.mu.Lock()
		if j.gen == f.gen && !f.closed {
			reportFailClosed(j.w, j.proc, j.pol, found, f.m)
		}
	}
	f.running = false
	f.idle.Broadcast()
}

// wait returns once no report is pending or being worked out.
func (f *failClosedReporter) wait() {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for f.running {
		f.idle.Wait()
	}
}

// busy reports whether the worker is up.
func (f *failClosedReporter) busy() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

// close drops any pending report, refuses later ones and waits for the one
// being worked out, which is not said: shutdown leaves no worker behind.
func (f *failClosedReporter) close() {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.closed, f.next = true, nil
	f.mu.Unlock()
	f.wait()
}

// deviceList is "on N device(s): " and the first failClosedDevices.
func deviceList(devices []string) string {
	noun := "devices"
	if len(devices) == 1 {
		noun = "device"
	}
	shown := devices
	if len(shown) > failClosedDevices {
		shown = shown[:failClosedDevices]
	}
	s := fmt.Sprintf("on %d %s: %s", len(devices), noun, strings.Join(shown, ", "))
	if more := len(devices) - len(shown); more > 0 {
		s += fmt.Sprintf(" and %d more", more)
	}
	return s
}
