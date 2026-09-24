package policy

import (
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/admission"
)

// selects reports whether the scope selects the device (spec §5.5): every
// match key must hold. A key the device has no value for resolves through
// on_missing, and so does a version the comparator cannot order — an
// incomparable version is treated exactly as a missing one, so a device
// whose patch level cannot be determined is assumed unpatched by a
// deny-bearing scope. byIncomparable reports a selection that happened only
// because of that, which spec §5.5 requires be reported, never silent.
func (s *Scope) selects(d admission.Device) (selected, byIncomparable bool) {
	keys := make([]string, 0, len(s.Match))
	for k := range s.Match {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value, present := d.Attributes[key]
		if key == "platform" {
			value, present = d.Platform, d.Platform != ""
		}
		if !present {
			if s.OnMissing != "include" {
				return false, false
			}
			continue
		}
		hit, comparable := s.matches(key, value)
		if !comparable {
			if s.OnMissing != "include" {
				return false, false
			}
			byIncomparable = true
			continue
		}
		if !hit {
			return false, false
		}
	}
	return true, byIncomparable
}

// matches tests one present value against one match term. comparable is
// false only when a version comparison could not order the two.
//
// A version-mitigation scope that attaches a deny should select the affected
// devices with lt (or lte) on the patched boundary, as spec §11's
// srx_unpatched does with `lt: "21.4R3-S5"`. A truncated version such as
// `21.4` orders below `21.4R3-S5` by the spec's prefix rule (§5.5), so lt
// keeps a device reporting a truncated version inside the mitigation; a
// scope written the other way would lift it.
func (s *Scope) matches(key, value string) (hit, comparable bool) {
	m := s.Match[key]
	if m.Equal != nil {
		return slices.Contains(m.Equal, value), true
	}
	for op, bound := range m.Cmp {
		if op == "re" {
			if !s.res[key].MatchString(value) {
				return false, true
			}
			continue
		}
		c, ok := CompareVersions(value, bound)
		if !ok {
			return false, false
		}
		var holds bool
		switch op {
		case "lt":
			holds = c < 0
		case "lte":
			holds = c <= 0
		case "gt":
			holds = c > 0
		case "gte":
			holds = c >= 0
		}
		if !holds {
			return false, true
		}
	}
	return true, true
}

// composition is what one subject holds on one device (spec §5.1, §5.5): the
// declared grants whose scope selects the device and that have not expired,
// the union of their roles with every role a selecting scope attaches for the
// subject's trust domain, the level the roles compose to, and the ceiling the
// grants compose to.
type composition struct {
	subject  *Subject
	grants   []*Grant
	roles    []string            // sorted
	attached map[string][]string // role → the scopes that attached it, for explain
	level    string
	ceiling  string
	// incomparable names every selecting scope that selected the device only
	// because a version could not be compared (spec §5.5: reported, never
	// silent).
	incomparable []string
}

// compose resolves sub on d at now. No selecting grant is an empty
// composition: attached roles have nothing to attach to, and never create
// access (spec §5.5). A zero now expires nothing, which is how the load-time
// checks see every grant.
func (p *Policy) compose(sub *Subject, d admission.Device, now time.Time) composition {
	c := composition{subject: sub, attached: map[string][]string{}}
	for _, g := range p.grants {
		if g.Subject != sub.Name {
			continue
		}
		if !g.Expires.IsZero() && !now.IsZero() && !now.Before(g.Expires) {
			continue
		}
		if ok, _ := p.scopes[g.Scope].selects(d); ok {
			c.grants = append(c.grants, g)
		}
	}
	if len(c.grants) == 0 {
		return c
	}
	// One order for everything a composition reports, independent of the
	// file's: which grant supplied an attribute is decided by it (spec §5.4).
	sort.SliceStable(c.grants, func(i, j int) bool {
		a, b := c.grants[i], c.grants[j]
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		return strings.Join(a.Roles, ",") < strings.Join(b.Roles, ",")
	})
	roles := map[string]bool{}
	for _, g := range c.grants {
		for _, r := range g.Roles {
			roles[r] = true
		}
		if p.levelIndex(g.MaxPrivilege) > p.levelIndex(c.ceiling) {
			c.ceiling = g.MaxPrivilege
		}
	}
	names := make([]string, 0, len(p.scopes))
	for name := range p.scopes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s := p.scopes[name]
		ok, byIncomparable := s.selects(d)
		if !ok {
			continue
		}
		if byIncomparable && (len(s.Attached[sub.Domain]) > 0 || c.grantsOn(name)) {
			c.incomparable = append(c.incomparable, name)
		}
		for _, r := range s.Attached[sub.Domain] {
			roles[r] = true
			c.attached[r] = append(c.attached[r], name)
		}
	}
	for r := range roles {
		c.roles = append(c.roles, r)
		if p.levelIndex(p.roles[r].Privilege) > p.levelIndex(c.level) {
			c.level = p.roles[r].Privilege
		}
	}
	sort.Strings(c.roles)
	return c
}

// grantsOn reports whether one of the composition's grants is on scope.
func (c composition) grantsOn(scope string) bool {
	for _, g := range c.grants {
		if g.Scope == scope {
			return true
		}
	}
	return false
}

// levelIndex is a level's place in the declared ordering, which is what the
// max-join uses (spec §6); "" is below every level.
func (p *Policy) levelIndex(level string) int {
	if level == "" {
		return -1
	}
	return slices.Index(p.levels, level)
}
