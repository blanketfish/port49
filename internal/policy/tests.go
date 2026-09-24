package policy

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
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

// commandRaw is CommandRaw as a device on platformName sends it: where the
// platform splits interface names (IOS-XE, tests/lab/results/
// L21-cisco_iosxe.md), an argument written as a name and an index joined
// arrives as the two, so it is sent as the two here, and split lists each
// such word. The daemon decides what the device sends, and explain and the
// policy tests must answer as it does.
func (p *Policy) commandRaw(line, platformName string) (raw, split []string) {
	raw = CommandRaw(line)
	if !p.dialect(platformName).SplitsInterfaceNames || len(raw) < 2 {
		return raw, nil
	}
	out := slices.Clone(raw[:2])
	for _, a := range raw[2:] {
		if head, index, ok := engine.SplitName(strings.TrimPrefix(a, "cmd-arg=")); ok {
			out = append(out, "cmd-arg="+head, "cmd-arg="+index)
			split = append(split, fmt.Sprintf("`%s` as `%s %s`", head+index, head, index))
			continue
		}
		out = append(out, a)
	}
	return out, split
}

// splitNotes is the caveat for a line commandRaw split on platformName.
func (p *Policy) splitNotes(line, platformName string) []string {
	_, split := p.commandRaw(line, platformName)
	if len(split) == 0 {
		return nil
	}
	return []string{fmt.Sprintf("%s splits an interface name from its index, so this was evaluated as IOS-XE sends "+
		"an interface name (tests/lab/results/L21-cisco_iosxe.md): %s; a word here that is not an interface name "+
		"reaches the device whole, and may be decided otherwise", platformName, strings.Join(split, ", "))}
}

// Decide resolves a subject (or, with principal set, a principal) on a device
// and decides one command line with the very blob a mint would write: encoded,
// decoded and compiled, the path the daemon takes, on the words the device
// sends for the line (commandRaw). It is what `port49 explain` and `port49
// policy test` both run.
func (p *Policy) Decide(subject, principal string, d admission.Device, line string, now time.Time) (Resolution, engine.Outcome, error) {
	res, err := p.resolveFor(subject, principal, d, now)
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
	raw, _ := p.commandRaw(line, d.Platform)
	return res, prog.Command(raw), nil
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
	// MintError is the mint item error the broker would answer instead of
	// minting (MintCheck), or device_unconfigured: the test is a deny and
	// carries no reason, since no decision is made.
	MintError string
	// Level and Ceiling are what the subject resolved to on the device, for
	// a test that asserts them; Ceiling is NoCeiling where the grants set
	// none.
	Level, Ceiling string
	// PrivLvl is the device privilege the session lands at, a number or
	// NoCeiling's `none`, and Enable the subject's mechanism, for a minted
	// session.
	PrivLvl, Enable string
	// Reply is the session reply, placeholders empty (sessionReply).
	Reply   []string
	Pass    bool
	Err     error
	Caveats []string
}

// Session reports whether the test asserts the session alone.
func (t Test) Session() bool { return strings.TrimSpace(t.Command) == "" }

// RunTests runs the file's tests against its inventory at now (spec §11,
// §12), answering in the mint's order as explain does: a principal with no
// grant on the device is a deny, no_grants_matched; a device with no platform
// is refused device_unconfigured; any principal on a quarantined device is a
// deny, device_quarantined; and a mint the broker would refuse (MintCheck)
// permits nothing. A session test (Session) passes where the mint would be
// made, with the level and ceiling it asserts.
func (p *Policy) RunTests(now time.Time) []TestResult {
	var out []TestResult
	for _, t := range p.tests {
		r := TestResult{Test: t}
		d, _ := p.device(t.Device)
		var res Resolution
		var o engine.Outcome
		var err error
		if t.Session() {
			res, err = p.resolveFor(t.Subject, t.Principal, d, now)
		} else {
			res, o, err = p.Decide(t.Subject, t.Principal, d, t.Command, now)
		}
		switch {
		case errors.Is(err, ErrNoGrants):
			r.Reason = decision.NoGrantsMatched
		case d.Platform == "":
			r.MintError = "device_unconfigured"
		case errors.Is(err, ErrDeviceQuarantined):
			r.Reason = decision.DeviceQuarantined
		case err != nil:
			r.Err = err
		default:
			if r.MintError, _ = mintCheck(res, p.principalsOf(t.Subject, t.Principal), d.Name); r.MintError != "" {
				break
			}
			r.Level, r.Ceiling, r.Enable, r.PrivLvl = res.Level, res.Ceiling, res.Enable, NoCeiling
			r.Reply = sessionReply(res)
			if r.Ceiling == "" {
				r.Ceiling = NoCeiling
			}
			if n, ok := p.devicePrivLvl(res, d.Platform); ok {
				r.PrivLvl = strconv.Itoa(int(n))
			}
			if t.Session() {
				break
			}
			r.Permit, r.Reason, r.Outcome = o.Permit, o.Reason, o
			r.Caveats = append(Caveats(d.Platform, p.dialect(d.Platform), o), p.splitNotes(t.Command, d.Platform)...)
		}
		// A level or ceiling is asserted of a session the mint would make,
		// so it fails wherever no level was resolved.
		minted := r.Err == nil && r.Ceiling != ""
		r.Pass = r.Err == nil && (t.Level == "" || minted && t.Level == r.Level) &&
			(t.MaxPrivilege == "" || minted && t.MaxPrivilege == r.Ceiling) &&
			(t.PrivLvl == "" || minted && samePrivLvl(t.PrivLvl, r.PrivLvl)) &&
			(t.Enable == "" || minted && t.Enable == r.Enable) &&
			(!t.AssertsReply || minted && slices.Equal(t.Reply, r.Reply))
		if t.Session() {
			r.Pass = r.Pass && minted
		} else {
			verdict := "deny"
			if r.Permit {
				verdict = "permit"
			}
			r.Pass = r.Pass && verdict == t.Expect && (t.Reason == "" || decision.Reason(t.Reason) == r.Reason)
		}
		out = append(out, r)
	}
	return out
}

// samePrivLvl compares an asserted priv_lvl with the resolved one, reading
// the number as a number, so `015` is 15.
func samePrivLvl(asserted, resolved string) bool {
	if asserted == resolved {
		return true
	}
	a, errA := strconv.Atoi(asserted)
	b, errB := strconv.Atoi(resolved)
	return errA == nil && errB == nil && a == b
}

// devicePrivLvl is the device privilege a resolved session lands at on a
// platform (spec §12): the priv-lvl its session reply sends after §6
// layering, read as the daemon reads it with the placeholders a mint cannot
// know left empty, or where the reply sends none, the number the platform
// gives the level. ok is false where neither says.
func (p *Policy) devicePrivLvl(res Resolution, platformName string) (uint8, bool) {
	if n, _, ok := engine.GrantedPrivLvl(sessionReply(res)); ok {
		return n, true
	}
	if res.Level == "" {
		return 0, false
	}
	return p.privLvl(p.dialect(platformName), res.Level)
}

// sessionReply is the session reply a resolution sends, after §6 layering,
// with the placeholders a mint cannot know left empty (spec §12): what the
// gate compares and a session test's reply: asserts. No privilege-bearing
// attribute carries a placeholder (checkAttributes), so what it leaves empty
// carries none.
func sessionReply(res Resolution) []string {
	attrs, err := res.Blob.SessionAttributes(engine.Values{})
	if err != nil {
		attrs = res.Blob.Attributes
	}
	return append([]string{}, attrs...)
}

// resolveFor resolves a subject, or with principal set a principal, on a
// device, as Decide does before it decides anything.
func (p *Policy) resolveFor(subject, principal string, d admission.Device, now time.Time) (Resolution, error) {
	if principal != "" {
		return p.Resolve(principal, d, now)
	}
	return p.ResolveSubject(subject, d, now)
}

// Dialect is the platform's dialect under this policy's environment.
func (p *Policy) Dialect(platformName string) platform.Dialect { return p.dialect(platformName) }

// Device looks a device up in the inventory the policy was loaded against.
func (p *Policy) Device(name string) (admission.Device, bool) { return p.device(name) }
