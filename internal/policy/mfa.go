package policy

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/admission"
)

// MFAMethod is one way a person proves a second factor at a login (spec
// §5.1.5; §13 decision 45).
type MFAMethod string

const (
	HardwareKeyTouch MFAMethod = "hardware_key_touch"
	IdPMFA           MFAMethod = "idp_mfa"
)

// mfaMethods is the vocabulary, in the order a requirement lists it.
var mfaMethods = []MFAMethod{HardwareKeyTouch, IdPMFA}

const (
	// defaultMFAReuse is how long one proof covers further logins when a
	// level leaves reuse_for out; maxMFAReuse the longest a level may say.
	defaultMFAReuse = 15 * time.Minute
	maxMFAReuse     = 8 * time.Hour
)

// machineMeets is what explain and `policy test` say of a requirement a
// machine meets (decision 45 ruling 21): a touch proves only from the token
// holding the connection key.
const machineMeets = "applies to this machine: provable only with a pkcs11 key and touch key on one token"

// PerLoginMFA is one level's per_login_mfa as written.
type PerLoginMFA struct {
	Accept            []MFAMethod
	ReuseFor          time.Duration
	AppliesToMachines bool
}

// MFALevel is one level that applies on a device: "defaults", "role
// <name>" or "scope <name>", and what it accepts.
type MFALevel struct {
	Level    string
	Accept   []MFAMethod
	ReuseFor time.Duration
	// AppliesToMachines is the level's own applies_to_machines, for explain.
	AppliesToMachines bool
	// Select is a scope level's match and on_missing, canonical: part of its
	// identity, so a scope that keeps its name and moves what it selects is
	// a different level. Empty for defaults and a role.
	Select string
}

// scopeSelect is a scope's match and on_missing as one canonical string, used
// both to compare two levels and to print them. Every key, value and pattern
// is quoted, so no value can read as a separator and two different selectors
// never encode alike. Value lists are sorted and deduplicated, since matching
// is set membership (scope.go), and on_missing is left out when no key can be
// missing: an empty match reads no key, and `name` is always present.
func scopeSelect(s *Scope) string {
	keys := make([]string, 0, len(s.Match))
	for k := range s.Match {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	terms := make([]string, len(keys))
	missable := false
	for i, k := range keys {
		missable = missable || k != "name"
		v := s.Match[k]
		var parts []string
		if len(v.Equal) > 0 {
			vals := slices.Clone(v.Equal)
			slices.Sort(vals)
			vals = slices.Compact(vals)
			quoted := make([]string, len(vals))
			for j, val := range vals {
				quoted[j] = strconv.Quote(val)
			}
			parts = append(parts, "in ["+strings.Join(quoted, ", ")+"]")
		}
		ops := make([]string, 0, len(v.Cmp))
		for op := range v.Cmp {
			ops = append(ops, op)
		}
		slices.Sort(ops)
		for _, op := range ops {
			parts = append(parts, op+" "+strconv.Quote(v.Cmp[op]))
		}
		terms[i] = strconv.Quote(k) + " " + strings.Join(parts, " ")
	}
	sel := "match {" + strings.Join(terms, ", ") + "}"
	if missable {
		sel += " on_missing " + strconv.Quote(s.OnMissing)
	}
	return sel
}

// MFARequirement is a device's effective requirement for one subject:
// Accept the intersection, ReuseFor the least, ReuseFrom the level that
// set it, and every level that applied. Levels is empty when there is none.
type MFARequirement struct {
	Accept    []MFAMethod
	ReuseFor  time.Duration
	ReuseFrom string
	Levels    []MFALevel
	// Machine is whether the subject is a workload, for explain: a machine's
	// requirement is read from the levels that apply to machines alone.
	Machine bool
}

func (r MFARequirement) Required() bool { return len(r.Levels) > 0 }

func (r MFARequirement) Accepts(m MFAMethod) bool { return slices.Contains(r.Accept, m) }

// String is the requirement as a test asserts it: `accept [..] reuse_for 5m`,
// or `none`.
func (r MFARequirement) String() string {
	if !r.Required() {
		return "none"
	}
	return mfaText(r.Accept, r.ReuseFor)
}

// explainLine is the requirement as `port49 explain` prints it, the default
// never invisible (decision 45 ruling 17): which levels intersect to what,
// where reuse_for comes from, and who it applies to.
func (r MFARequirement) explainLine() string {
	if !r.Required() {
		return "  per_login_mfa none"
	}
	levels := make([]string, len(r.Levels))
	for i, l := range r.Levels {
		levels[i] = l.Level
	}
	applies := "applies to humans"
	switch {
	case r.Machine:
		applies = machineMeets
	case slices.ContainsFunc(r.Levels, func(l MFALevel) bool { return l.AppliesToMachines }):
		applies = "applies to machines too"
	}
	return fmt.Sprintf("  per_login_mfa accept %s (%s); reuse_for %s (%s); %s", strings.Join(mfaNames(r.Accept), ", "),
		strings.Join(levels, " ∩ "), mfaDuration(r.ReuseFor), r.ReuseFrom, applies)
}

func mfaText(accept []MFAMethod, reuse time.Duration) string {
	names := make([]string, len(accept))
	for i, m := range accept {
		names[i] = string(m)
	}
	return "accept [" + strings.Join(names, ", ") + "] reuse_for " + mfaDuration(reuse)
}

// mfaDuration writes a duration as the policy file does: 5m, 8h, 0m.
func mfaDuration(d time.Duration) string {
	switch {
	case d == 0:
		return "0m"
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}

// ErrMFADisjoint is two levels on one device whose accept lists share no
// method.
var ErrMFADisjoint = errors.New("policy: per_login_mfa levels accept no common method")

// errMFAMachine is a machine principal left only a method it cannot prove.
var errMFAMachine = errors.New("policy: per_login_mfa: a machine principal proves by hardware_key_touch alone")

// isMFAError reports whether err is a per_login_mfa composition refusal.
func isMFAError(err error) bool {
	return errors.Is(err, ErrMFADisjoint) || errors.Is(err, errMFAMachine)
}

// mfaPairError is a per_login_mfa refusal that says which levels conflict:
// Pair names the two whose intersection is empty (for a machine, every level
// that applies to it). A quarantine entry carries it so a policy edit's
// "new" is a new device or level pair, whichever subject reaches it.
type mfaPairError struct {
	Err  error
	Pair string
}

func (e *mfaPairError) Error() string { return e.Err.Error() }
func (e *mfaPairError) Unwrap() error { return e.Err }

// mfaPair is the level pair err names, "" when it names none.
func mfaPair(err error) string {
	var pe *mfaPairError
	if errors.As(err, &pe) {
		return pe.Pair
	}
	return ""
}

// fileMFA is a per_login_mfa block as written. ReuseFor is a pointer, so an
// absent key takes the default and an empty one is refused.
type fileMFA struct {
	Accept            []string `yaml:"accept"`
	ReuseFor          *string  `yaml:"reuse_for"`
	AppliesToMachines bool     `yaml:"applies_to_machines"`
}

// fileDefaults is the `defaults:` block: the level that applies on every
// device.
type fileDefaults struct {
	PerLoginMFA *fileMFA `yaml:"per_login_mfa"`
}

// parseMFA checks one per_login_mfa block (decision 45 ruling 10); at names
// where it was written.
func parseMFA(at string, f *fileMFA) (*PerLoginMFA, error) {
	if f == nil {
		return nil, nil
	}
	if len(f.Accept) == 0 {
		return nil, fmt.Errorf("%s: accept is required and lists hardware_key_touch, idp_mfa or both; leave "+
			"per_login_mfa out for no requirement (spec §5.1.5)", at)
	}
	var accept []MFAMethod
	for i, name := range f.Accept {
		m := MFAMethod(name)
		switch {
		case !slices.Contains(mfaMethods, m):
			return nil, fmt.Errorf("%s: accept[%d] %q is not a method: use hardware_key_touch or idp_mfa", at, i, name)
		case slices.Contains(accept, m):
			return nil, fmt.Errorf("%s: accept lists %s twice", at, name)
		}
		accept = append(accept, m)
	}
	// The vocabulary's order, so a requirement reads and compares the same
	// however the file spells it.
	slices.SortFunc(accept, func(a, b MFAMethod) int { return slices.Index(mfaMethods, a) - slices.Index(mfaMethods, b) })
	reuse := defaultMFAReuse
	if f.ReuseFor != nil {
		var err error
		if reuse, err = parseMFAReuse(*f.ReuseFor); err != nil {
			return nil, fmt.Errorf("%s: %w", at, err)
		}
	}
	return &PerLoginMFA{Accept: accept, ReuseFor: reuse, AppliesToMachines: f.AppliesToMachines}, nil
}

func parseMFAReuse(s string) (time.Duration, error) {
	d, err := time.ParseDuration(s)
	switch {
	case err != nil:
		return 0, fmt.Errorf("reuse_for is a duration such as 15m, 0m for a proof at every login, at most 8h")
	case d < 0:
		return 0, fmt.Errorf("reuse_for must not be negative: 0m asks for a proof at every login")
	case d > maxMFAReuse:
		return 0, fmt.Errorf("reuse_for is at most 8h")
	}
	return d, nil
}

// fileTestMFA is a session test's per_login_mfa: the scalar `none`, or
// {accept, reuse_for}.
type fileTestMFA struct {
	None bool
	fileMFA
}

// MFAAssertion is what a session test asserts of a device's requirement: none,
// or the accept list as a set and reuse_for (default 15m, as in the policy).
type MFAAssertion struct {
	None     bool
	Accept   []MFAMethod
	ReuseFor time.Duration
}

func (a *MFAAssertion) String() string {
	if a == nil || a.None {
		return "none"
	}
	return mfaText(a.Accept, a.ReuseFor)
}

// Matches reports whether the requirement is the one asserted.
func (a *MFAAssertion) Matches(r MFARequirement) bool {
	if a.None {
		return !r.Required()
	}
	return r.Required() && r.ReuseFor == a.ReuseFor && sameMethods(a.Accept, r.Accept)
}

func sameMethods(a, b []MFAMethod) bool {
	return len(a) == len(b) && subsetOf(a, b) && subsetOf(b, a)
}

// subsetOf reports whether every method of a is in b.
func subsetOf(a, b []MFAMethod) bool {
	return !slices.ContainsFunc(a, func(m MFAMethod) bool { return !slices.Contains(b, m) })
}

// levelNames joins the levels' names with ", ".
func levelNames(levels []MFALevel) string { return strings.Join(levelsOf(levels), ", ") }

// levelsOf is the levels' names.
func levelsOf(levels []MFALevel) []string {
	names := make([]string, len(levels))
	for i, l := range levels {
		names[i] = l.Level
	}
	return names
}

// mfaFor is the requirement on d for c (decision 45 ruling 11): every
// level that applies, the intersection of their accept lists, the least
// reuse_for. A machine's composition reads only the levels that apply to
// machines.
func (p *Policy) mfaFor(c composition) (MFARequirement, error) {
	machine := c.subject.Domain == DomainMachines
	var levels []MFALevel
	add := func(name, sel string, m *PerLoginMFA) {
		if m == nil || machine && !m.AppliesToMachines {
			return
		}
		levels = append(levels, MFALevel{Level: name, Accept: m.Accept, ReuseFor: m.ReuseFor,
			AppliesToMachines: m.AppliesToMachines, Select: sel})
	}
	add("defaults", "", p.defaults.PerLoginMFA)
	for _, r := range c.roles {
		add("role "+r, "", p.roles[r].PerLoginMFA)
	}
	for _, s := range c.scopes {
		add("scope "+s, scopeSelect(p.scopes[s]), p.scopes[s].PerLoginMFA)
	}
	if len(levels) == 0 {
		return MFARequirement{Machine: machine}, nil
	}
	req := MFARequirement{Accept: slices.Clone(levels[0].Accept), ReuseFor: levels[0].ReuseFor,
		ReuseFrom: levels[0].Level, Levels: levels, Machine: machine}
	for _, l := range levels[1:] {
		next := slices.DeleteFunc(slices.Clone(req.Accept), func(m MFAMethod) bool { return !slices.Contains(l.Accept, m) })
		if len(next) == 0 {
			// With two methods an empty intersection always has an earlier
			// level disjoint from the one that emptied it, so the index below
			// is found; a third method added to the vocabulary must revisit
			// this: the intersection can then be empty with no two levels
			// disjoint.
			first := levels[slices.IndexFunc(levels, func(o MFALevel) bool {
				return !slices.ContainsFunc(o.Accept, func(m MFAMethod) bool { return slices.Contains(l.Accept, m) })
			})]
			return MFARequirement{}, &mfaPairError{Pair: first.Level + " | " + l.Level,
				Err: fmt.Errorf("%w: %s accepts %v and %s accepts %v", ErrMFADisjoint,
					first.Level, first.Accept, l.Level, l.Accept)}
		}
		req.Accept = next
		if l.ReuseFor < req.ReuseFor {
			req.ReuseFor, req.ReuseFrom = l.ReuseFor, l.Level
		}
	}
	if machine && !req.Accepts(HardwareKeyTouch) {
		return MFARequirement{}, &mfaPairError{Pair: strings.Join(levelsOf(levels), " | "),
			Err: fmt.Errorf("%w, and %s leave it %v", errMFAMachine, levelNames(levels), req.Accept)}
	}
	return req, nil
}

// mfaAt is the requirement subject holds on d at at, false where it holds no
// grant there or the composition has none (a quarantine says so).
func (p *Policy) mfaAt(subject string, d admission.Device, at time.Time) (MFARequirement, bool) {
	sub, ok := p.subs[subject]
	if !ok {
		return MFARequirement{}, false
	}
	c := p.compose(sub, d, at)
	if len(c.grants) == 0 {
		return MFARequirement{}, false
	}
	req, err := p.mfaFor(c)
	return req, err == nil
}

// MFADisjoint lists the quarantined devices with an entry whose cause is
// ErrMFADisjoint (or the machine refusal), only those entries kept: what a
// start or an inventory reload quarantines (ruling 11).
func (p *Policy) MFADisjoint() []Quarantine {
	var out []Quarantine
	for _, name := range sortedKeys(p.quarantine) {
		q := p.quarantine[name]
		var entries []QuarantineEntry
		for _, e := range q.Entries {
			if e.MFA {
				entries = append(entries, e)
			}
		}
		if len(entries) > 0 {
			out = append(out, Quarantine{Device: q.Device, Platform: q.Platform, Entries: entries})
		}
	}
	return out
}

// NewMFADisjoint is the entries of after.MFADisjoint() that base's lack,
// matched by device and conflicting level pair: what a policy edit
// introduces, and all a policy-file reload refuses (mfaRefusal). `policy diff`
// does not call it: it applies the same device-and-pair rule to each
// instant's entries (comparison.at). base is the in-force policy over the
// same inventory; nil base is
// every entry (re-review R5). A grant that only reaches a device already
// quarantined over the same pair is no new entry, whichever subject holds it:
// the device is out already, and an emergency grant at 3am must load (the
// controller's Task 9 review ruling, decision 45 ruling 11).
func NewMFADisjoint(base, after *Policy) []Quarantine {
	var had []Quarantine
	if base != nil {
		had = base.MFADisjoint()
	}
	var out []Quarantine
	for _, q := range after.MFADisjoint() {
		var fresh []QuarantineEntry
		for _, e := range q.Entries {
			known := slices.ContainsFunc(had, func(h Quarantine) bool {
				return h.Device == q.Device && slices.ContainsFunc(h.Entries, func(he QuarantineEntry) bool {
					return he.MFAPair == e.MFAPair
				})
			})
			if !known {
				fresh = append(fresh, e)
			}
		}
		if len(fresh) > 0 {
			out = append(out, Quarantine{Device: q.Device, Platform: q.Platform, Entries: fresh})
		}
	}
	return out
}

// MFAChange is a change to a subject's effective per-login requirement on
// devices (spec §12; decision 45 ruling 24). Weakened is a method added to
// accept, a longer reuse_for, a level gone (applies_to_machines turned off
// among them) or a requirement removed; Acknowledged is a passing session test
// in the new version, at At, on one of Devices, asserting the new
// per_login_mfa:. A tightening is Weakened false and never fails.
type MFAChange struct {
	Subject      string
	Devices      []string
	At           time.Time
	Old, New     MFARequirement
	Weakened     bool
	Acknowledged bool
}

// mfaWeakened is whether new lets a login through that old did not. It
// compares the effective requirement, and then each old level by identity (its
// kind and name, and for a scope its match and on_missing): a level gone or
// replaced by another, widened, given a longer reuse_for or turned off for
// machines is a weakening whatever the level count, so swapping a name-pinned
// scope for an attribute scope cannot pass (spec §12; decision 45 rulings 24
// and 26). Any change to a scope's match or on_missing counts as a removal,
// fail-closed: nothing proves the new selector covers a superset of devices
// now and after a later inventory sync. A rename counts as a removal too, and
// both need a session test; a level added is a tightening.
func mfaWeakened(old, new MFARequirement) bool {
	switch {
	case !old.Required():
		return false
	case !new.Required():
		return true
	}
	if !subsetOf(new.Accept, old.Accept) || new.ReuseFor > old.ReuseFor {
		return true
	}
	return slices.ContainsFunc(old.Levels, func(o MFALevel) bool {
		i := slices.IndexFunc(new.Levels, func(n MFALevel) bool { return n.Level == o.Level })
		if i < 0 {
			return true
		}
		n := new.Levels[i]
		return n.Select != o.Select || !subsetOf(n.Accept, o.Accept) || n.ReuseFor > o.ReuseFor ||
			o.AppliesToMachines && !n.AppliesToMachines
	})
}

// MetBy is whether a login made under prior meets r: r requires nothing, or
// prior required a proof from methods r accepts, reusable no longer than r
// allows. It compares the effective requirements alone, so a level added that
// leaves them unchanged is met; anything else added or tightened is not,
// fail-closed (a token minted under prior is superseded, final review I1).
func (r MFARequirement) MetBy(prior MFARequirement) bool {
	if !r.Required() {
		return true
	}
	return prior.Required() && subsetOf(prior.Accept, r.Accept) && prior.ReuseFor <= r.ReuseFor
}

// detail is the requirement with the levels that set it, `accept [..]
// reuse_for 5m (defaults ∩ scope core)`, a level that applies to machines
// marked, so a diff line never reads the same on both sides when only the
// levels moved. A scope that keeps its name on the other side and selects
// otherwise there shows its match and on_missing in brackets.
func (r MFARequirement) detail(other MFARequirement) string {
	if !r.Required() {
		return "none"
	}
	levels := make([]string, len(r.Levels))
	for i, l := range r.Levels {
		levels[i] = l.Level
		if slices.ContainsFunc(other.Levels, func(o MFALevel) bool { return o.Level == l.Level && o.Select != l.Select }) {
			levels[i] += " [" + l.Select + "]"
		}
		if l.AppliesToMachines {
			levels[i] += " (machines)"
		}
	}
	return r.String() + " (" + strings.Join(levels, " ∩ ") + ")"
}

// mfaKey names a requirement for an acknowledgment: what a session test
// asserts, so the accept list is a set.
func mfaKey(r MFARequirement) string {
	if !r.Required() {
		return "none"
	}
	accept := slices.Clone(r.Accept)
	slices.Sort(accept)
	return fmt.Sprint(accept) + "/" + r.ReuseFor.String()
}

// Line is the change as `policy diff` prints it; from is the " (from ...)" a
// change that first holds at a later expiry carries, or "". A weakening no
// session test asserts is `per_login_mfa_weakened:` and says what to add.
func (m MFAChange) Line(from string) string {
	label, tail := "per_login_mfa:", ""
	switch {
	case m.Weakened && m.Acknowledged:
		tail = " (weaker; a session test asserts it)"
	case m.Weakened:
		label = "per_login_mfa_weakened:"
		assert := "none"
		if m.New.Required() {
			assert = "{accept: [" + strings.Join(mfaNames(m.New.Accept), ", ") + "], reuse_for: " +
				mfaDuration(m.New.ReuseFor) + "}"
		}
		tail = "; no session test asserts it: add {subject: " + m.Subject + ", device: " + m.Devices[0] +
			", per_login_mfa: " + assert + "}"
	}
	return fmt.Sprintf("%s %s on %s%s: %s -> %s%s", label, m.Subject, strings.Join(m.Devices, ", "), from,
		m.Old.detail(m.New), m.New.detail(m.Old), tail)
}

func mfaNames(accept []MFAMethod) []string {
	out := make([]string, len(accept))
	for i, m := range accept {
		out[i] = string(m)
	}
	return out
}

// UnacknowledgedMFA counts the per_login_mfa weakenings no session test
// asserts.
func (d Diff) UnacknowledgedMFA() int {
	n := 0
	for _, c := range d.MFA {
		if c.Weakened && !c.Acknowledged {
			n++
		}
	}
	return n
}

// mfa compares subject's requirement on every device between the versions at
// at, one change per group of devices that moved alike. Only a device both
// versions compose is compared: a gained or lost grant is an access change,
// and a composition no method meets is a quarantine.
func (c *comparison) mfa(subject string, at time.Time) {
	type group struct {
		was, is MFARequirement
		devices []string
	}
	var order []string
	groups := map[string]*group{}
	for _, dev := range c.after.Devices() {
		was, wasOK := c.before.mfaAt(subject, dev, at)
		is, isOK := c.after.mfaAt(subject, dev, at)
		if !wasOK || !isOK || reflect.DeepEqual(was, is) {
			continue
		}
		key := fmt.Sprintf("%+v|%+v", was, is)
		if _, ok := groups[key]; !ok {
			groups[key] = &group{was: was, is: is}
			order = append(order, key)
		}
		groups[key].devices = append(groups[key].devices, dev.Name)
	}
	for _, key := range order {
		g := groups[key]
		if !c.once("per_login_mfa", subject, strings.Join(g.devices, ","), key) {
			continue
		}
		ch := MFAChange{Subject: subject, Devices: g.devices, At: at, Old: g.was, New: g.is,
			Weakened: mfaWeakened(g.was, g.is)}
		ch.Acknowledged = ch.Weakened && slices.ContainsFunc(g.devices, func(device string) bool {
			return c.acks[mfaAckKey(at, subject, device, g.is)]
		})
		c.d.MFA = append(c.d.MFA, ch)
	}
}

func mfaAckKey(at time.Time, subject, device string, r MFARequirement) string {
	return instantKey(at, subject, "per_login_mfa", device, mfaKey(r))
}
