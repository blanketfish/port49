package policy

import (
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/engine"
)

// ShadowedDeny is one deny a subject holds that a permit it also holds
// overrides for some command (spec §5.4, §12): the report that replaces the
// guarantee deny-overrides gave. It names the deny, the subject it fails to
// bind, and the permit that beats it.
type ShadowedDeny struct {
	Subject                            string
	Deny, DenyRole, Permit, PermitRole string
	// Platforms are where the pair meets: the platforms of the devices the
	// subject holds both rules on.
	Platforms []string
	// Possible is an overlap two regex or class terms decide, which is not
	// decidable cheaply (engine.Shadow).
	Possible bool
	// Acknowledged is a policy test for this subject that expects permit on
	// a command where this permit wins over this deny (spec §12).
	Acknowledged bool
}

// ShadowedDenies computes the shadowed-deny report over every subject on every
// device the policy loaded against, for every composition reachable from now:
// the one in force now, and the one left at each later instant a grant
// expires. A device is skipped only at an instant it is quarantined, since
// nothing is minted for it then; one an expiry brings back is read with what
// that expiry leaves. One row per subject and rule pair, in name order.
func (p *Policy) ShadowedDenies(now time.Time) []ShadowedDeny {
	instants := p.expiryInstants(now)
	acks := p.shadowAcks(instants)
	rows := map[string]*ShadowedDeny{}
	for _, at := range instants {
		for _, d := range p.env.Devices {
			if _, q := p.Quarantined(d.Name, at); q {
				continue
			}
			for name, sub := range p.subs {
				res, err := p.resolve(sub, d, at)
				if err != nil {
					continue
				}
				prog, err := engine.Compile(res.Blob)
				if err != nil {
					continue
				}
				for _, s := range prog.Shadows() {
					key := shadowKey(name, s.Deny.Role, s.Deny.Rule, s.Permit.Role, s.Permit.Rule)
					row, ok := rows[key]
					if !ok {
						row = &ShadowedDeny{Subject: name, Deny: s.Deny.Rule, DenyRole: s.Deny.Role,
							Permit: s.Permit.Rule, PermitRole: s.Permit.Role, Possible: s.Possible, Acknowledged: acks[key]}
						rows[key] = row
					}
					if !slices.Contains(row.Platforms, d.Platform) {
						row.Platforms = append(row.Platforms, d.Platform)
						slices.Sort(row.Platforms)
					}
				}
			}
		}
	}
	out := make([]ShadowedDeny, 0, len(rows))
	for _, r := range rows {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return shadowKey(a.Subject, a.DenyRole, a.Deny, a.PermitRole, a.Permit) <
			shadowKey(b.Subject, b.DenyRole, b.Deny, b.PermitRole, b.Permit)
	})
	return out
}

// expiryInstants is now and every later instant a grant expires, in order:
// the only instants at which a composition, and so a quarantine, can change.
func (p *Policy) expiryInstants(now time.Time) []time.Time {
	instants := []time.Time{now}
	for _, g := range p.grants {
		if g.Expires.After(now) && !slices.ContainsFunc(instants, g.Expires.Equal) {
			instants = append(instants, g.Expires)
		}
	}
	slices.SortFunc(instants[1:], func(a, b time.Time) int { return a.Compare(b) })
	return instants
}

// shadowAcks is every (subject, deny, permit) a passing permit test exercises
// at one of instants: on a permit, every matching permit whose tuple
// dominates a matching deny's wins over that deny on the tested command, so
// the author has seen each of those pairs happen (spec §12).
func (p *Policy) shadowAcks(instants []time.Time) map[string]bool {
	acks := map[string]bool{}
	for _, at := range instants {
		for _, r := range p.RunTests(at) {
			if !r.Pass || !r.Permit {
				continue
			}
			subject := r.Test.Subject
			if subject == "" {
				subject = p.byID[r.Test.Principal]
			}
			for _, pm := range r.Outcome.Permits {
				for _, d := range r.Outcome.Denies {
					if engine.Dominates(pm.Specificity, d.Specificity) {
						acks[shadowKey(subject, d.Role, d.Rule, pm.Role, pm.Rule)] = true
					}
				}
			}
		}
	}
	return acks
}

func shadowKey(parts ...string) string { return strings.Join(parts, "\x00") }
