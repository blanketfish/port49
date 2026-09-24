package policy

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
)

// CommandRaw is the authorization request a device sends for a typed command
// line: `service=shell`, the first word as `cmd`, the rest as `cmd-arg`, the
// words kept exactly as typed.
func CommandRaw(line string) []string {
	f := strings.Fields(line)
	if len(f) == 0 {
		return []string{"service=shell"}
	}
	raw := []string{"service=shell", "cmd=" + f[0]}
	for _, a := range f[1:] {
		raw = append(raw, "cmd-arg="+a)
	}
	return raw
}

// Decide resolves a subject (or, with principal set, a principal) on a device
// and decides one command line with the very blob a mint would write: encoded,
// decoded and compiled, the path the daemon takes. It is what `port49
// explain` and `port49 policy test` both run.
func (p *Policy) Decide(subject, principal string, d admission.Device, line string, now time.Time) (Resolution, engine.Outcome, error) {
	var res Resolution
	var err error
	if principal != "" {
		res, err = p.Resolve(principal, d, now)
	} else {
		res, err = p.ResolveSubject(subject, d, now)
	}
	if err != nil {
		return res, engine.Outcome{}, err
	}
	body, hash, err := engine.Encode(res.Blob)
	if err != nil {
		return res, engine.Outcome{}, err
	}
	b, err := engine.Decode(hash, body)
	if err != nil {
		return res, engine.Outcome{}, err
	}
	prog, err := engine.Compile(b)
	if err != nil {
		return res, engine.Outcome{}, err
	}
	return res, prog.Command(CommandRaw(line)), nil
}

// Caveats are what port49's answer does not promise on this platform (spec
// §4, "Platform caveat"; §5.6, "Where these controls do not reach"; §12):
// explain and the policy tests must say so rather than report a decision the
// device will not honor.
func Caveats(platformName string, dialect platform.Dialect, o engine.Outcome) []string {
	var out []string
	if !dialect.Authorizes("commands") {
		out = append(out, fmt.Sprintf("%s does not send per-command authorization (supports: %s): the device "+
			"never asks port49 about this command, and a revocation or a session ceiling does not reach a live "+
			"session there (spec §5.6)", platformName, strings.Join(dialect.Supports, ", ")))
	}
	if len(o.Pipeline) > 0 && !dialect.PipeAuthorized {
		out = append(out, fmt.Sprintf("%s applies output modifiers itself after port49 authorizes the bare "+
			"command (pipe_authorized: false; tests/lab/results/L2-*.md), so the device never sends this "+
			"pipeline and no pipe rule protects it; the control is on the device", platformName))
	}
	return out
}

// TestResult is one `tests:` entry's run.
type TestResult struct {
	Test    Test
	Permit  bool
	Reason  decision.Reason
	Outcome engine.Outcome
	Pass    bool
	Err     error
	Caveats []string
}

// RunTests runs the file's tests against its inventory at now (spec §11,
// §12). A principal with no grant on the device is a deny, no_grants_matched,
// and any principal on a quarantined device a deny, device_quarantined: each is
// what the mint would answer.
func (p *Policy) RunTests(now time.Time) []TestResult {
	var out []TestResult
	for _, t := range p.tests {
		r := TestResult{Test: t}
		d, _ := p.device(t.Device)
		_, o, err := p.Decide(t.Subject, t.Principal, d, t.Command, now)
		switch {
		case errors.Is(err, ErrNoGrants):
			r.Reason = decision.NoGrantsMatched
		case errors.Is(err, ErrDeviceQuarantined):
			r.Reason = decision.DeviceQuarantined
		case err != nil:
			r.Err = err
		default:
			r.Permit, r.Reason, r.Outcome = o.Permit, o.Reason, o
			r.Caveats = Caveats(d.Platform, p.dialect(d.Platform), o)
		}
		verdict := "deny"
		if r.Permit {
			verdict = "permit"
		}
		r.Pass = r.Err == nil && verdict == t.Expect && (t.Reason == "" || decision.Reason(t.Reason) == r.Reason)
		out = append(out, r)
	}
	return out
}

// Dialect is the platform's dialect under this policy's environment.
func (p *Policy) Dialect(platformName string) platform.Dialect { return p.dialect(platformName) }

// Device looks a device up in the inventory the policy was loaded against.
func (p *Policy) Device(name string) (admission.Device, bool) { return p.device(name) }
