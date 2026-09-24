package policy

import (
	"fmt"
	"slices"
	"time"
)

// ReviewRow is one grant row a subject appears in, as access review renders
// it (spec §12): the flat grant table is the report, not an investigation.
type ReviewRow struct {
	Scope        string
	Roles        []string
	MaxPrivilege string
	Expires      time.Time // zero: never
	Expired      bool
	// Devices is how many devices in the inventory the scope selects now.
	Devices int
}

// Review lists every grant row naming subject, in file order, with its
// scope's size against the inventory and whether it has expired at now.
func (p *Policy) Review(subject string, now time.Time) ([]ReviewRow, error) {
	if _, ok := p.subs[subject]; !ok {
		return nil, fmt.Errorf("subject %q is not declared", subject)
	}
	var out []ReviewRow
	for _, g := range p.Grants(subject) {
		row := ReviewRow{Scope: g.Scope, Roles: slices.Clone(g.Roles), MaxPrivilege: g.MaxPrivilege, Expires: g.Expires,
			Expired: !g.Expires.IsZero() && !now.Before(g.Expires)}
		for _, d := range p.env.Devices {
			if ok, _ := p.scopes[g.Scope].selects(d); ok {
				row.Devices++
			}
		}
		out = append(out, row)
	}
	return out, nil
}

// ServedUsernames is every username port49 would mint a token under for the
// device at now, by the subject that claims it: each identity-list subject a
// grant reaches the device with. A group subject's usernames come from the
// directory one per member (plan 7), so groups names the group subjects that
// reach it, whose members the check cannot list.
func (p *Policy) ServedUsernames(device string, now time.Time) (usernames map[string]string, groups []string, err error) {
	d, ok := p.device(device)
	if !ok {
		return nil, nil, fmt.Errorf("device %q is not in the inventory", device)
	}
	usernames = map[string]string{}
	for _, name := range sortedKeys(p.subs) {
		s := p.subs[name]
		if len(p.compose(s, d, now).grants) == 0 {
			continue
		}
		if s.Group != "" {
			groups = append(groups, name)
			continue
		}
		usernames[s.Username] = name
	}
	return usernames, groups, nil
}
