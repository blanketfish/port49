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
// device the policy loaded against, with every grant in force (a zero time
// expires nothing, as the load-time checks read them). A device quarantined
// with every grant in force is skipped: nothing is minted for it. One row per
// subject and rule pair, in name order.
func (p *Policy) ShadowedDenies() []ShadowedDeny {
	acks := p.shadowAcks()
	rows := map[string]*ShadowedDeny{}
	for name, sub := range p.subs {
		for _, d := range p.env.Devices {
			if _, q := p.Quarantined(d.Name, time.Time{}); q {
				continue
			}
			res, err := p.resolve(sub, d, time.Time{})
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
					row = &ShadowedDeny{Subject: name, Deny: s.Deny.Rule, DenyRole: s.Deny.Role, Permit: s.Permit.Rule,
						PermitRole: s.Permit.Role, Possible: s.Possible, Acknowledged: acks[key]}
					rows[key] = row
				}
				if !slices.Contains(row.Platforms, d.Platform) {
					row.Platforms = append(row.Platforms, d.Platform)
					slices.Sort(row.Platforms)
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

// shadowAcks is every (subject, deny, permit) a passing permit test
// exercises: on a permit, every deny that matched is one the deciding permit
// overrode (engine.Outcome.Denies), so the author has seen it happen.
func (p *Policy) shadowAcks() map[string]bool {
	acks := map[string]bool{}
	for _, r := range p.RunTests(time.Time{}) {
		if !r.Pass || !r.Permit || r.Outcome.Decided == nil {
			continue
		}
		subject := r.Test.Subject
		if subject == "" {
			subject = p.byID[r.Test.Principal]
		}
		for _, d := range r.Outcome.Denies {
			acks[shadowKey(subject, d.Role, d.Rule, r.Outcome.Decided.Role, r.Outcome.Decided.Rule)] = true
		}
	}
	return acks
}

func shadowKey(parts ...string) string { return strings.Join(parts, "\x00") }
