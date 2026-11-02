package policy

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/blanketfish/port49/internal/admission"
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
		switch key {
		case "platform":
			value, present = d.Platform, d.Platform != ""
		case "name":
			// The inventory name, which pins a scope to named devices
			// (spec §10); an attribute of that name is not read.
			value, present = d.Name, true
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

// matches tests one present value against one match term. Every comparison
// on the key is evaluated, so the answer never depends on the order they are
// visited in (spec §5.4): if any version comparison cannot order the two,
// comparable is false and the key goes to on_missing whatever the others say;
// otherwise the key holds only if every comparison holds.
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
	hit, comparable = true, true
	for op, bound := range m.Cmp {
		if op == "re" {
			hit = hit && s.res[key].MatchString(value)
			continue
		}
		c, ok := CompareVersions(value, bound)
		if !ok {
			comparable = false
			continue
		}
		switch op {
		case "lt":
			hit = hit && c < 0
		case "lte":
			hit = hit && c <= 0
		case "gt":
			hit = hit && c > 0
		case "gte":
			hit = hit && c >= 0
		}
	}
	if !comparable {
		return false, false
	}
	return hit, true
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
	// scopes names every scope that selects the device, sorted, grant or not:
	// a scope carries a per-login level wherever it selects (spec §5.1.5).
	scopes []string
	// incomparable names every selecting scope that selected the device only
	// because a version could not be compared (spec §5.5: reported, never
	// silent).
	incomparable []string
	// notCounted names the max_privilege of a grant of a subject with enable
	// none that the ceiling counts only up to the level its roles reach
	// (spec §5.1), for the refusal that follows from it.
	notCounted []string
}

// compose resolves sub on d at now. No selecting grant is an empty
// composition: attached roles have nothing to attach to, and never create
// access (spec §5.5). A zero now expires nothing, which is how the load-time
// checks see every grant.
func (p *Policy) compose(sub *Subject, d admission.Device, now time.Time) composition {
	return p.composeAll([]*Subject{sub}, d, now)
}

// composeAll is compose for every subject a principal matches (plan 7g,
// Ruling 5): the grants of any of subs, composed as one. Every subject a human
// principal matches is in the humans domain, so subs[0]'s domain is the one
// attached roles read.
func (p *Policy) composeAll(subs []*Subject, d admission.Device, now time.Time) composition {
	sub := subs[0]
	c := composition{subject: sub, attached: map[string][]string{}}
	for _, i := range p.grantIndexes(subs) {
		g := p.grants[i]
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
	// Composed subjects reach by enable no ceiling that none of them offers
	// escalation to alone: where one of them offers it, a subject with enable
	// none contributes to the ceiling only the level its roles reach, capped
	// by its own max_privilege, what it holds without enabling (Ruling
	// PF7g-i; spec §5.1). It never creates a ceiling: with none stated by
	// the subjects that offer escalation there is none.
	escalates := false
	for _, g := range c.grants {
		escalates = escalates || p.subs[g.Subject].Enable != "none"
	}
	composed := len(subs) > 1 && escalates
	held := "" // the none subjects' contribution
	roles := map[string]bool{}
	for _, g := range c.grants {
		level := ""
		for _, r := range g.Roles {
			roles[r] = true
			if p.levelIndex(p.roles[r].Privilege) > p.levelIndex(level) {
				level = p.roles[r].Privilege
			}
		}
		if !composed || p.subs[g.Subject].Enable != "none" {
			if p.levelIndex(g.MaxPrivilege) > p.levelIndex(c.ceiling) {
				c.ceiling = g.MaxPrivilege
			}
			continue
		}
		limit := level
		if g.MaxPrivilege != "" && p.levelIndex(g.MaxPrivilege) < p.levelIndex(level) {
			limit = g.MaxPrivilege
		}
		if g.MaxPrivilege != "" && p.levelIndex(g.MaxPrivilege) > p.levelIndex(limit) {
			c.notCounted = append(c.notCounted, fmt.Sprintf("%s's max_privilege %s", g.Subject, g.MaxPrivilege))
		}
		if p.levelIndex(limit) > p.levelIndex(held) {
			held = limit
		}
	}
	if c.ceiling != "" && p.levelIndex(held) > p.levelIndex(c.ceiling) {
		c.ceiling = held
	}
	for _, name := range p.scopeNames {
		s := p.scopes[name]
		ok, byIncomparable := s.selects(d)
		if !ok {
			continue
		}
		c.scopes = append(c.scopes, name)
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

// grantIndexes are the indexes into p.grants of every grant of any of subs, in
// file order, each once: a subject listed twice must not double its grants.
// One subject's list is the stored one, which a caller must not change; several
// are merged into a fresh slice (their file order is the sort of the indexes).
func (p *Policy) grantIndexes(subs []*Subject) []int {
	if len(subs) == 1 {
		return p.grantsOf[subs[0].Name]
	}
	var idx []int
	for _, s := range subs {
		idx = append(idx, p.grantsOf[s.Name]...)
	}
	slices.Sort(idx)
	return slices.Compact(idx)
}

// deviceClass is everything compose and resolve read of a device, as one
// comparable key: its platform, whose adapter compiles and projects the
// composition, and one mark per scope, in Policy.scopeNames order: '-' the
// scope does not select the device, '?' it selects it only by a version it
// could not compare, '+' it selects it. compose reads the device's name and
// attributes only through selects. Two devices in one class resolve alike for
// every subject at every moment, but for the name an error quotes (the
// per_login_mfa refusal, resolve.go's "(on %s)") and the name a mint's
// {device} placeholder fills, which a reader that shares a class's result
// must not take from a representative (the 12c Task 6b brief's input
// inventory, R6 and R14).
type deviceClass struct{ platform, marks string }

// String is the class as signature writes it.
func (c deviceClass) String() string { return c.platform + "\x00" + c.marks }

// classOf is d's class over scopes, every scope's name, sorted (sortedKeys).
func (p *Policy) classOf(d admission.Device, scopes []string) deviceClass {
	marks := make([]byte, len(scopes))
	for i, name := range scopes {
		switch ok, byIncomparable := p.scopes[name].selects(d); {
		case !ok:
			marks[i] = '-'
		case byIncomparable:
			marks[i] = '?'
		default:
			marks[i] = '+'
		}
	}
	return deviceClass{platform: d.Platform, marks: string(marks)}
}

// signature is d's class as a string, for readers that group by it
// (projectionGroupsBy).
func (p *Policy) signature(d admission.Device, scopes []string) string {
	return p.classOf(d, scopes).String()
}

// deviceClasses groups devs by class: the indexes of each class, classes in
// order of first appearance and indexes ascending.
func (p *Policy) deviceClasses(devs []admission.Device) [][]int {
	var classes [][]int
	at := map[deviceClass]int{}
	for i, d := range devs {
		c := p.classOf(d, p.scopeNames)
		k, ok := at[c]
		if !ok {
			k = len(classes)
			at[c] = k
			classes = append(classes, nil)
		}
		classes[k] = append(classes[k], i)
	}
	return classes
}

// granting is the subjects of subs, in order, with at least one grant in the
// composition.
func (c composition) granting(subs []*Subject) []*Subject {
	var out []*Subject
	for _, s := range subs {
		if slices.ContainsFunc(c.grants, func(g *Grant) bool { return g.Subject == s.Name }) {
			out = append(out, s)
		}
	}
	return out
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

// Scopes is every declared scope, by name: what the bundle diff compares
// membership of across a swap (spec §10).
func (p *Policy) Scopes() []*Scope {
	out := make([]*Scope, 0, len(p.scopes))
	for _, name := range sortedKeys(p.scopes) {
		out = append(out, p.scopes[name])
	}
	return out
}

// Selects reports whether the scope selects the device, as a grant reads it.
func (s *Scope) Selects(d admission.Device) bool {
	ok, _ := s.selects(d)
	return ok
}
