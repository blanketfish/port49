package policy

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
)

// Explanation is `port49 explain`'s answer (spec §12): one hypothetical
// decision, with exactly one reason, the rule and role behind it, the roles
// that would permit a denied command, and what the device will not honor.
type Explanation struct {
	Subject, Device, Platform string
	// Command is empty for a session: what the login would be told.
	Command    string
	Resolution Resolution
	// NoGrants is no_grants_matched: nothing else is filled in.
	NoGrants bool
	// Quarantined is device_quarantined, and Quarantine the causes the device
	// fails a joint check with at the time asked (spec §10). Nothing else is
	// filled in but notes.
	Quarantined bool
	Quarantine  []string
	// Refused is device_unknown on a device the inventory names and
	// admission refuses (spec §10), with why. Nothing else is filled in.
	Refused string
	// MintError is the mint item error the broker would answer instead of a
	// token (attribute_too_long, attribute_unsafe, broker_error), and
	// MintDetail what it names. Nothing is decided past it: no token, no
	// session, no command.
	MintError, MintDetail string
	Outcome               engine.Outcome
	// WouldPermit names the roles, held or not, whose permits alone match a
	// denied command on this platform: what to ask for, or what a deny beats.
	WouldPermit []string
	Caveats     []string
	// hidden are the values a redaction hides in the line and the policy's
	// rules: Render quotes text derived from the line through them
	// (platform.QuoteShown).
	hidden []string
}

// Explain resolves a subject (or a principal) on a device and decides one
// command line, or the session when line is empty, with the evaluator the
// daemon runs, after the checks the broker runs before it mints.
//
// It names a device missing from the inventory as such, which suits an
// offline tool whose operator holds the inventory. An API that reuses it
// (spec §12, explain_others) must answer an unknown device as
// no_grants_matched, as the broker does, or it tells the caller which devices
// exist (design §17).
func (p *Policy) Explain(subject, principal, device, line string, now time.Time) (Explanation, error) {
	d, ok := p.device(device)
	if !ok {
		return Explanation{}, fmt.Errorf("device %q is not in the inventory", device)
	}
	if principal != "" {
		name, ok := p.byID[principal]
		if !ok {
			return Explanation{Subject: principal, Device: device, Platform: d.Platform, Command: line, NoGrants: true}, nil
		}
		subject = name
	}
	if _, ok := p.subs[subject]; !ok {
		return Explanation{}, fmt.Errorf("subject %q is not declared", subject)
	}
	e := Explanation{Subject: subject, Device: device, Platform: d.Platform, Command: line,
		hidden: append(platform.HiddenValues(p.Redactions(), strings.Fields(line)), p.HiddenValues()...)}
	dialect := p.dialect(d.Platform)
	var res Resolution
	var o engine.Outcome
	var err error
	// Resolve answers in the mint's order: no grant on the device before the
	// quarantine, so explain names a quarantine only to a subject granted there.
	if line == "" {
		res, err = p.ResolveSubject(subject, d, now)
	} else {
		res, o, err = p.Decide(subject, "", d, line, now)
	}
	switch {
	case errors.Is(err, ErrNoGrants):
		e.NoGrants = true
		return e, nil
	case d.Platform == "":
		// The broker names an inventory device with no platform as the
		// inventory fault it is, after the grants and before the quarantine
		// the policy put it in at load (internal/broker, mintOne).
		e.MintError, e.MintDetail = "device_unconfigured",
			"inventory gives this device no platform, so the broker cannot compile its policy; give it one"
		return e, nil
	case errors.Is(err, ErrDeviceQuarantined):
		e.Quarantined = true
		e.Quarantine, e.Caveats = p.quarantineAt(d.Name, now)
		return e, nil
	case errors.Is(err, ErrDeviceRefused):
		e.Refused = p.admitted[d.Name].Refused
		return e, nil
	case err != nil:
		return e, err
	}
	// A quarantine an expiry will bring on has not failed yet: the device
	// answers now, and the note says from when it will not.
	_, e.Caveats = p.quarantineAt(d.Name, now)
	e.Resolution = res
	principals := p.principalsOf(subject, principal)
	if e.MintError, e.MintDetail = mintCheck(res, principals, device); e.MintError != "" {
		return e, nil
	}
	if len(principals) == 0 && slices.ContainsFunc(res.Blob.Attributes, func(a string) bool {
		return strings.Contains(a, "{principal}")
	}) {
		e.Caveats = append(e.Caveats, fmt.Sprintf("%s is a group subject, so {principal} was filled in empty when "+
			"the session reply was checked: a member's principal is filled in at mint, and a long one may still be "+
			"refused attribute_too_long; ask with --principal to check one", subject))
	}
	if !dialect.ShowsServerMsg && dialect.Authorizes("commands") {
		e.Caveats = append(e.Caveats, fmt.Sprintf("%s never displays port49's server_msg: it prints its own error "+
			"for a denied command, so the session-ceiling warning, a context_stale notice and a credential_revoked "+
			"notice reach nobody there (spec §5.6; tests/lab/results/L2-cisco_nxos.md)", d.Platform))
	}
	if line == "" {
		// The daemon decodes and compiles the blob at session authorization
		// (Decide does for a command); one it cannot is a defect, not a permit.
		body, hash, err := engine.Encode(res.Blob)
		if err == nil {
			var b engine.Blob
			if b, err = engine.Decode(hash, body); err == nil {
				_, err = engine.Compile(b)
			}
		}
		if err != nil {
			return e, err
		}
		if !dialect.Authorizes("commands") {
			e.Caveats = append(e.Caveats, fmt.Sprintf("%s does not send per-command authorization (supports: %s): "+
				"no command in this session is asked of port49, and a revocation or a session ceiling does not "+
				"reach a live session there (spec §5.6)", d.Platform, strings.Join(dialect.Supports, ", ")))
		}
		if pr := res.Projection; pr != nil {
			e.Caveats = append(e.Caveats, fmt.Sprintf("the reply projects these rules as the %s shape (spec §8): what "+
				"the device runs is its class ∩ the wire, and the class half is the device's configuration, outside "+
				"port49 (port49 platform export --classes prints the reference)", pr.Shape))
			if pr.FailClosed != "" {
				e.Caveats = append(e.Caveats, fmt.Sprintf("the composition cannot be told to %s faithfully (%s): %s; "+
					"this subject gets the fail-closed reply there, and policy test fails on it (spec §13 decision 26)",
					d.Platform, pr.FailClosed, pr.Refusal.Why))
			}
		}
		return e, nil
	}
	e.Outcome = o
	e.Caveats = append(e.Caveats, Caveats(d.Platform, dialect, o)...)
	e.Caveats = append(e.Caveats, ProjectionCaveats(res, d.Platform, o, e.hidden)...)
	e.Caveats = append(e.Caveats, p.splitNotes(line, d.Platform)...)
	// Spec §12: explain MUST say so where `supports` lacks config_commands. No
	// built-in platform declares it (internal/platform), so a command typed in
	// configuration mode is not known to reach port49 at all.
	if dialect.Authorizes("commands") && !dialect.Authorizes("config_commands") {
		e.Caveats = append(e.Caveats, fmt.Sprintf("%s does not declare config_commands: whether a command typed in "+
			"configuration mode is sent to port49 at all is unmeasured, so if this is a configuration-mode command "+
			"the device may apply it whatever this answer says (spec §9, §12)", d.Platform))
	}
	// A pipe stage denial is about the pipe allowlist; the command's permits
	// already match, so who would permit the command is not the question.
	if !o.Permit && o.Reason != decision.PipeStageDenied {
		if e.WouldPermit, err = p.wouldPermit(line, d.Platform); err != nil {
			return e, err
		}
	}
	return e, nil
}

// MintCheck is what the broker runs on a resolution before it mints for one
// principal on one device (internal/broker, mintOne), and what explain, the
// policy tests and the diff run so they answer as it does: the blob must
// encode, and the session reply must fill in within the wire's limits. code
// is the mint item error, empty when the mint may go ahead: attribute_too_long
// for a reply past 255 bytes, attribute_unsafe for a filled-in value carrying
// a separator or control character (the fault is in the data, not the
// broker), and broker_error for anything else.
func MintCheck(res Resolution, principal, device string) (code, detail string) {
	if _, _, err := engine.Encode(res.Blob); err != nil {
		return "broker_error", err.Error()
	}
	_, err := res.Blob.SessionAttributes(engine.Values{Username: res.Username, Principal: principal, Device: device})
	switch {
	case err == nil:
		return "", ""
	case errors.Is(err, engine.ErrAttributeTooLong):
		return "attribute_too_long", err.Error()
	case errors.Is(err, engine.ErrSubstitution):
		return "attribute_unsafe", err.Error()
	}
	return "broker_error", err.Error()
}

// mintCheck is MintCheck for each of principals, the first refusal naming
// the principal. With none to try (a group subject), {principal} is filled in
// empty, and Explain says so.
func mintCheck(res Resolution, principals []string, device string) (code, detail string) {
	if len(principals) == 0 {
		principals = []string{""}
	}
	for _, pr := range principals {
		if code, detail := MintCheck(res, pr, device); code != "" {
			return code, fmt.Sprintf("for %s: %s", pr, detail)
		}
	}
	return "", ""
}

// principalsOf are the principals a mint for subject may be asked for: the
// one given, or the subject's identities.
func (p *Policy) principalsOf(subject, principal string) []string {
	if principal != "" {
		return []string{principal}
	}
	if sub, ok := p.subs[subject]; ok {
		return sub.Identity
	}
	return nil
}

// quarantineAt splits the device's quarantine entries at now: the causes that
// quarantine it now, and a note for each an expiry will bring on (spec §10).
func (p *Policy) quarantineAt(device string, now time.Time) (causes, scheduled []string) {
	for _, q := range p.Quarantines(now) {
		if q.Device != device {
			continue
		}
		for _, qe := range q.Entries {
			if qe.Current(now) {
				causes = append(causes, qe.Cause)
			} else {
				scheduled = append(scheduled, qe.Message(now))
			}
		}
	}
	return causes, scheduled
}

// wouldPermit lists every role whose permits alone match the command on this
// platform, compiled as the daemon would compile them. A permit naming a class
// the platform does not define cannot match there and is skipped; any other
// failure is an error, since every permit passed load and a role dropped
// silently would read as "permitted by none".
func (p *Policy) wouldPermit(line, platformName string) ([]string, error) {
	dialect := p.dialect(platformName)
	raw, _ := p.commandRaw(line, platformName)
	var out []string
	for name, r := range p.roles {
		// This blob is never minted; Compile only needs a bundle named.
		b := engine.Blob{Version: engine.Version, Bundle: "explain", Platform: platformName, Classes: dialect.EntityClasses,
			Normalize: p.normalizeFor(platformName)}
		for _, rule := range r.Permit {
			missing, err := missingClass(rule, dialect.EntityClasses)
			if err != nil {
				return nil, fmt.Errorf("role %q: %w", name, err)
			}
			if !missing {
				b.Rules = append(b.Rules, engine.Rule{Verdict: engine.Permit, Rule: rule, Role: name})
			}
		}
		prog, err := engine.Compile(b)
		if err != nil {
			return nil, fmt.Errorf("role %q: %w", name, err)
		}
		if len(prog.Command(raw).Permits) > 0 {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

func missingClass(rule string, classes map[string][]string) (bool, error) {
	terms, err := engine.ParseRule(rule)
	if err != nil {
		return false, err
	}
	for _, t := range terms {
		if t.Kind == engine.Class {
			if _, ok := classes[t.Text]; !ok {
				return true, nil
			}
		}
	}
	return false, nil
}

// Redacted is e with the command asked about and every rule it names
// redacted by rules, as the daemon's records are (spec §5.8): what explain
// prints may land in a log, and a rule literal is no safer there than a
// typed secret.
func (e Explanation) Redacted(rules []platform.Redaction) Explanation {
	if words, ok := platform.Redact(rules, strings.Fields(e.Command)); ok {
		e.Command = strings.Join(words, " ")
	}
	one := func(m engine.Match) engine.Match {
		if words, ok := platform.RedactRule(rules, strings.Fields(m.Rule)); ok {
			m.Rule = strings.Join(words, " ")
		}
		return m
	}
	all := func(ms []engine.Match) []engine.Match {
		out := slices.Clone(ms)
		for i := range out {
			out[i] = one(out[i])
		}
		return out
	}
	o := &e.Outcome
	if o.Decided != nil {
		m := one(*o.Decided)
		o.Decided = &m
	}
	if o.Deny != nil {
		m := one(*o.Deny)
		o.Deny = &m
	}
	o.Permits, o.Denies = all(o.Permits), all(o.Denies)
	return e
}

// Render writes the explanation for a person: the verdict and its one reason
// first, then what it rests on.
func (e Explanation) Render(w io.Writer, showAttributes bool) {
	if e.Refused != "" {
		fmt.Fprintf(w, "deny %s\n  %s (%s) is in the inventory and admission refuses it: %s; nothing is minted "+
			"for it, and port49d closes its connections after the header (spec §10)\n", decision.DeviceUnknown,
			e.Device, e.Platform, e.Refused)
		return
	}
	if e.Quarantined {
		fmt.Fprintf(w, "deny %s\n  %s (%s) fails a joint check now, so nothing is minted for it and port49d "+
			"closes its connections without a reply while the check fails (spec §10):\n",
			decision.DeviceQuarantined, e.Device, e.Platform)
		for _, c := range e.Quarantine {
			fmt.Fprintf(w, "    %s\n", c)
		}
		for _, c := range e.Caveats {
			fmt.Fprintf(w, "note: %s\n", c)
		}
		return
	}
	if e.NoGrants {
		fmt.Fprintf(w, "deny %s\n  %s holds no grant whose scope selects %s (%s); attached roles never add a "+
			"device (spec §5.5)\n", decision.NoGrantsMatched, e.Subject, e.Device, e.Platform)
		return
	}
	if e.MintError != "" {
		fmt.Fprintf(w, "refused %s: the broker mints no token for %s on %s (%s), so there is no session to "+
			"decide\n  %s\n", e.MintError, e.Subject, e.Device, platformName(e.Platform), e.MintDetail)
		for _, c := range e.Caveats {
			fmt.Fprintf(w, "note: %s\n", c)
		}
		return
	}
	r := e.Resolution
	o := e.Outcome
	if e.Command == "" {
		fmt.Fprintf(w, "permit %s (session)\n", r.Blob.SessionReason())
	} else if o.Permit {
		fmt.Fprintf(w, "permit %s\n", o.Reason)
	} else {
		fmt.Fprintf(w, "deny %s\n", o.Reason)
	}
	fmt.Fprintf(w, "  subject     %s\n  device      %s (%s)\n", e.Subject, e.Device, e.Platform)
	var grants []string
	for _, g := range r.Grants {
		s := g.Scope + " [" + strings.Join(g.Roles, " ") + "]"
		if g.Expires != "" {
			s += " expires " + g.Expires
		}
		grants = append(grants, s)
	}
	fmt.Fprintf(w, "  grants      %s\n", strings.Join(grants, "; "))
	var roles []string
	for _, name := range r.Roles {
		if scopes, ok := r.Attached[name]; ok {
			name += " (attached by " + strings.Join(scopes, ", ") + ")"
		}
		roles = append(roles, name)
	}
	fmt.Fprintf(w, "  roles       %s\n", strings.Join(roles, ", "))
	level := r.Level
	if level == "" {
		level = "(none)"
	}
	ceiling := "none"
	if r.Ceiling != "" {
		ceiling = fmt.Sprintf("%s (priv-lvl %d)", r.Ceiling, r.MaxPrivilege)
	}
	fmt.Fprintf(w, "  level       %s; max_privilege %s\n", level, ceiling)
	for _, s := range r.Incomparable {
		fmt.Fprintf(w, "  scope       %s selected this device because its version could not be compared (spec §5.5)\n", s)
	}
	if e.Command != "" {
		fmt.Fprintf(w, "  command     %s\n", e.Command)
		switch o.Reason {
		case decision.PermitDominates:
			fmt.Fprintf(w, "  rule        %s (%s) %v\n", o.Decided.Rule, o.Decided.Role, o.Decided.Specificity)
			if o.Deny != nil {
				fmt.Fprintf(w, "  overrides   %s (%s) %v: the permit dominates it at every position\n",
					o.Deny.Rule, o.Deny.Role, o.Deny.Specificity)
			}
		case decision.NoPermitDominatesDeny:
			fmt.Fprintf(w, "  rule        %s (%s) %v\n", o.Deny.Rule, o.Deny.Role, o.Deny.Specificity)
			for _, pm := range o.Permits {
				fmt.Fprintf(w, "  permit      %s (%s) %v does not dominate it\n", pm.Rule, pm.Role, pm.Specificity)
			}
		case decision.PipeStageDenied:
			fmt.Fprintf(w, "  rule        %s (%s) %v permits the command\n", o.Decided.Rule, o.Decided.Role,
				o.Decided.Specificity)
			fmt.Fprintf(w, "  stage       %d, %s, matches no pipe permit\n", o.Stage,
				platform.QuoteShown(e.hidden, strings.Join(o.Pipeline[o.Stage-1], " ")))
		case decision.NoRuleMatched:
			fmt.Fprintf(w, "  rule        no permit matches\n")
		}
		if !o.Permit && o.Reason != decision.PipeStageDenied {
			wp := "none"
			if len(e.WouldPermit) > 0 {
				wp = strings.Join(e.WouldPermit, ", ")
			}
			fmt.Fprintf(w, "  permitted by %s\n", wp)
		}
	}
	if showAttributes || e.Command == "" {
		fmt.Fprintf(w, "session attributes that would be returned:\n")
		if len(r.Attributes) == 0 {
			fmt.Fprintf(w, "  (none)\n")
		}
		for _, a := range r.Attributes {
			kind := "optional"
			if engine.Mandatory(a.Attribute) {
				kind = "mandatory"
			}
			fmt.Fprintf(w, "  %-32s (%s)  <- %s\n", a.Attribute, kind, a.Source)
			for _, s := range a.Shadows {
				fmt.Fprintf(w, "  %-32s    shadows %s\n", "", s)
			}
		}
	}
	for _, c := range e.Caveats {
		fmt.Fprintf(w, "note: %s\n", c)
	}
}
