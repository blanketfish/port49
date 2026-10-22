package port49d

import (
	"fmt"
	"strings"
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
// sets port49_policy_fail_closed_compositions to how many hold now. The
// count line comes first and is said when that is above 0 or was before, so
// a fix is said as a fault is. The finding quotes the policy's own text,
// and stderr is a log: it is redacted as sayPolicy redacts (spec §5.8).
// It is said at start, after every swap's refresh pass and after every
// pass that crossed a grant expiry.
func sayFailClosed(proc string, pol *policy.Policy, now time.Time, m *metrics.Metrics) {
	if m == nil || pol == nil {
		return
	}
	found := pol.FailClosedCompositions(now)
	n := 0
	for _, f := range found {
		if !f.Later {
			n++
		}
	}
	before := m.SetPolicyFailClosed(n)
	redact := pol.Redactions()
	say := func(format string, args ...any) {
		fmt.Fprintln(stderr, platform.RedactQuoted(redact, proc+": "+fmt.Sprintf(format, args...)))
	}
	if n > 0 || before > 0 {
		say("policy: %d composition(s) answered fail-closed now (port49 policy test names them)", n)
	}
	for _, f := range found {
		say("policy: %s: %s; %s", f.Kind, f.Message, deviceList(f.Devices))
	}
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
