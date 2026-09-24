package policy

import (
	"fmt"
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
		row := ReviewRow{Scope: g.Scope, Roles: g.Roles, MaxPrivilege: g.MaxPrivilege, Expires: g.Expires,
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
