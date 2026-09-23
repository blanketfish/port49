package policy

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/blob"
	"github.com/rhwendt/port49/internal/decision"
)

// Resolution is what one mint needs from policy for one principal on one
// device (spec §5.1): the subject, the device-facing username, the subject's
// ceilings, the grants that selected the device (for the mint record), and
// the compiled blob.
type Resolution struct {
	Subject, Username, Enable string
	TokenTTL                  time.Duration
	MaxPrivilege              uint8
	Grants                    []decision.PolicyGrant
	Blob                      blob.Blob
}

// SubjectOf names the subject a principal resolves to, if any.
func (p *Policy) SubjectOf(principal string) (string, bool) {
	name, ok := p.byIdentity[principal]
	return name, ok
}

// Resolve evaluates spec §5.1 for principal on a device of platform. Every
// grant is on all_devices, so every grant of the subject selects every device
// and the platform is the only fact about the device that matters. false is
// no_grants_matched: no subject lists the principal, or its subject holds no
// grant — the same answer either way (design §17).
func (p *Policy) Resolve(principal, platform string) (Resolution, bool) {
	name, ok := p.byIdentity[principal]
	if !ok {
		return Resolution{}, false
	}
	grants := p.grants[name]
	if len(grants) == 0 {
		return Resolution{}, false
	}
	s := p.subjects[name]
	res := Resolution{Subject: name, Username: s.Username, Enable: s.Enable, TokenTTL: s.TokenTTL}
	seen := map[string]bool{}
	permit, deny := map[string]bool{}, map[string]bool{}
	var level uint8
	for _, g := range grants {
		res.Grants = append(res.Grants, decision.PolicyGrant{Scope: g.Scope, Roles: append([]string(nil), g.Roles...)})
		// Max over the grants; an absent max_privilege is zero, which is no
		// ceiling at all (store.Context.PrivilegeCeiling), not a ceiling of zero.
		if l := levels[g.MaxPrivilege]; l > res.MaxPrivilege {
			res.MaxPrivilege = l
		}
		for _, rn := range g.Roles {
			if seen[rn] {
				continue
			}
			seen[rn] = true
			r := p.roles[rn]
			if l := levels[r.Privilege]; l > level {
				level = l
			}
			for _, x := range r.Permit {
				permit[normalize(x)] = true
			}
			for _, x := range r.Deny {
				deny[normalize(x)] = true
			}
		}
	}
	res.Blob = blob.Blob{Platform: platform, Privilege: level, Attributes: sessionAttributes(platform, level),
		Permit: sorted(permit), Deny: sorted(deny)}
	return res, true
}

// sessionAttributes renders the session authorization reply for one
// platform. BORROWED AHEAD from plan 5: `arista_eos` only, `priv-lvl=N`, which
// vEOS applies on every lab run since 2026-09-20
// (tests/lab/results/L16-arista_eos.md). Every other platform gets no
// attributes — the one reply no measured platform ends a session over — and
// plan 5's adapters fill them in (plan 3, Question 2).
func sessionAttributes(platform string, level uint8) []string {
	if platform == "arista_eos" && level > 0 {
		return []string{"priv-lvl=" + strconv.Itoa(int(level))}
	}
	return nil
}

func normalize(rule string) string { return strings.Join(strings.Fields(rule), " ") }

func sorted(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}
