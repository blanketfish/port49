package policy

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
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
	// Quarantine is device_quarantined: the causes the device failed a joint
	// check at load with (spec §10). Nothing else is filled in.
	Quarantine []string
	Outcome    engine.Outcome
	// WouldPermit names the roles, held or not, whose permits alone match a
	// denied command on this platform: what to ask for, or what a deny beats.
	WouldPermit []string
	Caveats     []string
}

// Explain resolves a subject (or a principal) on a device and decides one
// command line, or the session when line is empty, with the evaluator the
// daemon runs.
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
	e := Explanation{Subject: subject, Device: device, Platform: d.Platform, Command: line}
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
	case errors.Is(err, ErrDeviceQuarantined):
		e.Quarantine, e.Caveats = p.quarantineAt(d.Name, now)
		return e, nil
	case err != nil:
		return e, err
	}
	// A quarantine an expiry will bring on has not failed yet: the device
	// answers now, and the note says from when it will not.
	_, e.Caveats = p.quarantineAt(d.Name, now)
	if line == "" {
		e.Resolution = res
		e.Caveats = append(e.Caveats, Caveats(d.Platform, dialect, engine.Outcome{})...)
		return e, nil
	}
	e.Resolution, e.Outcome = res, o
	e.Caveats = append(e.Caveats, Caveats(d.Platform, dialect, o)...)
	// Spec §12: explain MUST say so where `supports` lacks config_commands. No
	// built-in platform declares it (internal/platform), so a command typed in
	// configuration mode is not known to reach port49 at all.
	if dialect.Authorizes("commands") && !dialect.Authorizes("config_commands") {
		e.Caveats = append(e.Caveats, fmt.Sprintf("%s does not declare config_commands: whether a command typed in "+
			"configuration mode is sent to port49 at all is unmeasured, so if this is a configuration-mode command "+
			"the device may apply it whatever this answer says (spec §9, §12)", d.Platform))
	}
	if !o.Permit {
		e.WouldPermit = p.wouldPermit(line, d.Platform)
	}
	return e, nil
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
// the platform does not define cannot match there and is skipped.
func (p *Policy) wouldPermit(line, platformName string) []string {
	dialect := p.dialect(platformName)
	raw := CommandRaw(line)
	var out []string
	for name, r := range p.roles {
		// This blob is never minted; Compile only needs a bundle named.
		b := engine.Blob{Version: engine.Version, Bundle: "explain", Platform: platformName, Classes: dialect.EntityClasses,
			Normalize: engine.Normalize{PipeToken: dialect.PipeToken, StripCR: dialect.StripCR}}
		for _, rule := range r.Permit {
			if !missingClass(rule, dialect.EntityClasses) {
				b.Rules = append(b.Rules, engine.Rule{Verdict: engine.Permit, Rule: rule, Role: name})
			}
		}
		if prog, err := engine.Compile(b); err == nil && len(prog.Command(raw).Permits) > 0 {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func missingClass(rule string, classes map[string][]string) bool {
	terms, err := engine.ParseRule(rule)
	if err != nil {
		return true
	}
	for _, t := range terms {
		if t.Kind == engine.Class {
			if _, ok := classes[t.Text]; !ok {
				return true
			}
		}
	}
	return false
}

// Render writes the explanation for a person: the verdict and its one reason
// first, then what it rests on.
func (e Explanation) Render(w io.Writer, showAttributes bool) {
	if len(e.Quarantine) > 0 {
		fmt.Fprintf(w, "deny %s\n  %s (%s) failed a joint check at load, so nothing is minted for it and port49d "+
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
	r := e.Resolution
	o := e.Outcome
	if e.Command == "" {
		fmt.Fprintf(w, "permit %s (session)\n", decision.ContextMatched)
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
			fmt.Fprintf(w, "  stage       %d, %q, matches no pipe permit\n", o.Stage, strings.Join(o.Pipeline[o.Stage-1], " "))
		case decision.NoRuleMatched:
			fmt.Fprintf(w, "  rule        no permit matches\n")
		}
		if !o.Permit {
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
