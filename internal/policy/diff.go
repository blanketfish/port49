package policy

import (
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
)

// Diff is the effective-permission diff between two versions of a policy
// loaded against the same inventory (spec §5.4, §12): every command whose
// verdict moved, for every subject, on the devices that hold the same blobs
// before and after; every level and ceiling that moved; every device that
// gained or lost a subject's access outright; every changed rule carrying a
// regex or class term, which the diff cannot enumerate; and every device the
// new version quarantines that the old did not.
type Diff struct {
	Changes     []Change
	Access      []AccessChange
	Levels      []LevelChange
	Regex       []RegexChange
	Quarantined []Quarantine
}

// Change is one command whose verdict moved.
type Change struct {
	Subject string
	Devices []string
	// Command is Vector joined by spaces. Vector is the command exactly as
	// probed: an argument may carry whitespace, which a deny reads trimmed
	// and a permit does not (spec §3), and only Vector keeps it.
	Command  string
	Vector   []string
	Old, New engine.Outcome
	// Gated is spec §12's privilege-expansion gate: a command a deny refused
	// that the new version permits. Acknowledged is a policy test in the new
	// version that exercises that permit over that deny.
	Gated, Acknowledged bool
}

// AccessChange is a subject gaining or losing every grant on some devices.
// It is one line, not one per command.
type AccessChange struct {
	Subject string
	Devices []string
	Gained  bool
}

// LevelChange is a privilege change (spec §6): the level the roles compose
// to, or the ceiling the grants do.
type LevelChange struct {
	Subject                                    string
	Devices                                    []string
	OldLevel, NewLevel, OldCeiling, NewCeiling string
}

// RegexChange is a rule carrying a regex or class term that one version has
// and the other does not. Commands it matches are not enumerated, because a
// regex position is not (spec §12, "Effective-permission diff in CI").
type RegexChange struct {
	Subject string
	Devices []string
	Rule    engine.Rule
	Added   bool
}

// Unacknowledged counts the gated changes no test exercises.
func (d Diff) Unacknowledged() int {
	n := 0
	for _, c := range d.Changes {
		if c.Gated && !c.Acknowledged {
			n++
		}
	}
	return n
}

// side is one version's view of one subject on one device.
type side struct {
	prog        *engine.Program
	res         Resolution
	hash        string
	quarantined bool
}

func (p *Policy) side(subject string, d admission.Device) side {
	if _, ok := p.Quarantined(d.Name, time.Time{}); ok {
		return side{quarantined: true}
	}
	sub, ok := p.subs[subject]
	if !ok {
		return side{}
	}
	res, err := p.resolve(sub, d, time.Time{})
	if err != nil {
		return side{}
	}
	_, hash, err := engine.Encode(res.Blob)
	if err != nil {
		return side{}
	}
	prog, err := engine.Compile(res.Blob)
	if err != nil {
		return side{}
	}
	return side{prog: prog, res: res, hash: hash}
}

// decide is the side's answer to one command vector, each argument sent as
// it is: no grant is a deny, no_grants_matched, as the mint would answer.
func (s side) decide(vector []string) engine.Outcome {
	if s.prog == nil {
		return engine.Outcome{Reason: decision.NoGrantsMatched}
	}
	raw := []string{"service=shell", "cmd=" + vector[0]}
	for _, a := range vector[1:] {
		raw = append(raw, "cmd-arg="+a)
	}
	return s.prog.Command(raw)
}

// Compare computes the diff from before to after, every grant in force. The
// two must have been loaded against the same inventory; after's is the one
// walked.
func Compare(before, after *Policy) Diff {
	var d Diff
	// A zero time holds every entry, current or one an expiry brings on: a
	// quarantine the change schedules is as much the change's as one it
	// starts now.
	quarantinedBefore := map[string]bool{}
	for _, q := range before.Quarantines(time.Time{}) {
		quarantinedBefore[q.Device] = true
	}
	for _, q := range after.Quarantines(time.Time{}) {
		if !quarantinedBefore[q.Device] {
			d.Quarantined = append(d.Quarantined, q)
		}
	}
	names := map[string]bool{}
	for n := range before.subs {
		names[n] = true
	}
	for n := range after.subs {
		names[n] = true
	}
	subjects := make([]string, 0, len(names))
	for n := range names {
		subjects = append(subjects, n)
	}
	sort.Strings(subjects)
	acks := after.expansionAcks(before)
	type group struct {
		was, is side
		devices []string
	}
	for _, subject := range subjects {
		var order []string
		groups := map[string]*group{}
		for _, dev := range after.Devices() {
			was, is := before.side(subject, dev), after.side(subject, dev)
			if was.quarantined || is.quarantined || (was.prog == nil && is.prog == nil) {
				continue
			}
			// The ceiling is the grants', not the blob's, so it is part of
			// what makes two devices alike.
			key := was.hash + "|" + was.res.Ceiling + "|" + is.hash + "|" + is.res.Ceiling
			if _, ok := groups[key]; !ok {
				groups[key] = &group{was: was, is: is}
				order = append(order, key)
			}
			groups[key].devices = append(groups[key].devices, dev.Name)
		}
		for _, key := range order {
			g := groups[key]
			if g.was.prog == nil || g.is.prog == nil {
				d.Access = append(d.Access, AccessChange{Subject: subject, Devices: g.devices, Gained: g.was.prog == nil})
				continue
			}
			was, is := g.was.res, g.is.res
			if was.Level != is.Level || was.Ceiling != is.Ceiling {
				d.Levels = append(d.Levels, LevelChange{Subject: subject, Devices: g.devices, OldLevel: was.Level,
					NewLevel: is.Level, OldCeiling: was.Ceiling, NewCeiling: is.Ceiling})
			}
			if g.was.hash == g.is.hash {
				continue
			}
			d.Regex = append(d.Regex, regexChanges(subject, g.devices, was.Blob.Rules, is.Blob.Rules)...)
			for _, v := range engine.Probes(g.was.prog, g.is.prog) {
				from, to := g.was.decide(v), g.is.decide(v)
				if from.Permit == to.Permit {
					continue
				}
				c := Change{Subject: subject, Devices: g.devices, Command: strings.Join(v, " "), Vector: v, Old: from,
					New: to}
				if !from.Permit && from.Deny != nil {
					c.Gated = true
					c.Acknowledged = acks[shadowKey(subject, from.Deny.Role, from.Deny.Rule, to.Decided.Role,
						to.Decided.Rule)]
				}
				d.Changes = append(d.Changes, c)
			}
		}
	}
	return d
}

// regexChanges lists the rules carrying a regex or class term that one side
// has and the other does not.
func regexChanges(subject string, devices []string, was, is []engine.Rule) []RegexChange {
	var out []RegexChange
	for _, v := range []struct {
		have, other []engine.Rule
		added       bool
	}{{is, was, true}, {was, is, false}} {
		for _, r := range v.have {
			if !constrained(r.Rule) || slices.Contains(v.other, r) {
				continue
			}
			out = append(out, RegexChange{Subject: subject, Devices: devices, Rule: r, Added: v.added})
		}
	}
	return out
}

func constrained(rule string) bool {
	terms, _ := engine.ParseRule(rule)
	for _, t := range terms {
		if t.Kind == engine.Regex || t.Kind == engine.Class {
			return true
		}
	}
	return false
}

// expansionAcks is every (subject, deny, permit) a passing permit test in p
// exercises where before refused the same command with that deny: the test is
// the author saying the expansion is meant (spec §12).
func (p *Policy) expansionAcks(before *Policy) map[string]bool {
	acks := map[string]bool{}
	for _, r := range p.RunTests(time.Time{}) {
		if !r.Pass || !r.Permit || r.Outcome.Decided == nil {
			continue
		}
		subject := r.Test.Subject
		if subject == "" {
			subject = p.byID[r.Test.Principal]
		}
		dev, ok := p.device(r.Test.Device)
		if !ok {
			continue
		}
		_, was, err := before.Decide(subject, "", dev, r.Test.Command, time.Time{})
		if err != nil && !errors.Is(err, ErrNoGrants) {
			continue
		}
		if !was.Permit && was.Deny != nil {
			acks[shadowKey(subject, was.Deny.Role, was.Deny.Rule, r.Outcome.Decided.Role,
				r.Outcome.Decided.Rule)] = true
		}
	}
	return acks
}
