package policy

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
)

// ErrNoGrants is no_grants_matched: no subject lists the principal, or no
// declared grant of its subject selects the device (spec §5.1, §5.5). The mint
// answers it the same either way (design §17).
var ErrNoGrants = errors.New("policy: no declared grant for this principal selects the device")

// Resolution is what one mint, one explanation or one policy test needs from
// policy for one principal on one device (spec §5.1).
type Resolution struct {
	Subject, Username, Enable string
	TokenTTL                  time.Duration
	// Level is the level the roles compose to; Ceiling the max_privilege the
	// grants compose to. MaxPrivilege is Ceiling as this platform's priv-lvl
	// number, the form the token and the daemon compare; HasCeiling says
	// whether there is one, so priv-lvl 0 is a ceiling and not its absence.
	Level, Ceiling string
	MaxPrivilege   uint8
	HasCeiling     bool
	// Grants are the grants that selected the device, for the mint record.
	Grants []decision.PolicyGrant
	// Roles are every role that composed, attached ones included; Attached
	// says which scope attached each attached one.
	Roles    []string
	Attached map[string][]string
	// Incomparable names scopes that selected the device only because a
	// version could not be compared (spec §5.5).
	Incomparable []string
	// Blob is the compiled decision; Attributes says where each of its
	// attributes came from and what it shadowed (spec §6).
	Blob       engine.Blob
	Attributes []AttributeSource
}

// AttributeSource is one attribute of the session reply and its provenance:
// the platform's level, a role, or a grant, and every value it overrode
// (spec §6, "Diagnosing an unfamiliar vendor").
type AttributeSource struct {
	Attribute string
	Source    string
	Shadows   []string
}

// Resolve evaluates spec §5.1 for a principal on a device at now: the subject
// its identity names, the grants whose scope selects the device and that
// have not expired, every role they and the device's scopes carry, and the
// compiled blob.
func (p *Policy) Resolve(principal string, d admission.Device, now time.Time) (Resolution, error) {
	name, ok := p.byID[principal]
	if !ok {
		return Resolution{}, ErrNoGrants
	}
	return p.resolveNow(p.subs[name], d, now)
}

// ResolveSubject is Resolve for a subject named directly, as the offline
// tools name them: a group subject has no identity to resolve by until plan 7
// reads the directory.
func (p *Policy) ResolveSubject(subject string, d admission.Device, now time.Time) (Resolution, error) {
	sub, ok := p.subs[subject]
	if !ok {
		return Resolution{}, fmt.Errorf("policy: subject %q is not declared", subject)
	}
	return p.resolveNow(sub, d, now)
}

// resolveNow is resolve behind the quarantine at now. A subject with no grant
// on the device is answered ErrNoGrants before the quarantine is asked: the
// mint API must not tell a caller which devices exist (design §17), and a
// quarantine names one.
func (p *Policy) resolveNow(sub *Subject, d admission.Device, now time.Time) (Resolution, error) {
	c := p.compose(sub, d, now)
	if len(c.grants) == 0 {
		return Resolution{}, ErrNoGrants
	}
	if err := p.quarantined(d, now); err != nil {
		return Resolution{}, err
	}
	return p.resolved(sub, d, c)
}

// resolve is resolveNow without the quarantine: what the joint checks, the
// diff and lint read.
func (p *Policy) resolve(sub *Subject, d admission.Device, now time.Time) (Resolution, error) {
	c := p.compose(sub, d, now)
	if len(c.grants) == 0 {
		return Resolution{}, ErrNoGrants
	}
	return p.resolved(sub, d, c)
}

// resolved turns a composition with grants into its resolution and blob.
func (p *Policy) resolved(sub *Subject, d admission.Device, c composition) (Resolution, error) {
	res := Resolution{Subject: sub.Name, Username: sub.Username, Enable: sub.Enable, TokenTTL: sub.TokenTTL,
		Level: c.level, Ceiling: c.ceiling, Roles: c.roles, Attached: c.attached, Incomparable: c.incomparable}
	for _, g := range c.grants {
		pg := decision.PolicyGrant{Scope: g.Scope, Roles: append([]string(nil), g.Roles...)}
		if !g.Expires.IsZero() {
			pg.Expires = decision.FormatTime(g.Expires)
		}
		res.Grants = append(res.Grants, pg)
	}
	dialect := p.dialect(d.Platform)
	if c.ceiling != "" {
		n, ok := p.privLvl(dialect, c.ceiling)
		if !ok {
			return Resolution{}, fmt.Errorf("max_privilege %s has no priv-lvl number on %s; the token's ceiling "+
				"cannot be stated to the daemon", c.ceiling, d.Platform)
		}
		// The token reads a zero max_privilege as none (store.Context.
		// PrivilegeCeiling), so a ceiling of 0 would be minted as no ceiling.
		if n == 0 {
			return Resolution{}, fmt.Errorf("max_privilege %s is priv-lvl 0 on %s, which the token cannot carry: "+
				"it reads zero as no ceiling; use a level numbered 1 or above", c.ceiling, d.Platform)
		}
		res.MaxPrivilege, res.HasCeiling = n, true
	}
	var err error
	res.Blob, res.Attributes, err = p.compile(c, d, dialect)
	return res, err
}

// compile turns a composition into the blob for one platform (spec §5.1.2):
// every role's rules, each carrying its role; the pipe allowlist of every
// role that permits anything; the patterns behind every class a rule names,
// as this platform defines them; and the session attributes, layered.
func (p *Policy) compile(c composition, d admission.Device, dialect platform.Dialect) (engine.Blob, []AttributeSource, error) {
	b := engine.Blob{Version: engine.Version, Bundle: p.Bundle, Platform: d.Platform, Privilege: c.level,
		Normalize: p.normalizeFor(d.Platform), Classes: map[string][]string{}}
	pipe := map[string]bool{}
	for _, name := range c.roles {
		r := p.roles[name]
		for _, rule := range r.Permit {
			b.Rules = append(b.Rules, engine.Rule{Verdict: engine.Permit, Rule: rule, Role: name})
		}
		for _, rule := range r.Deny {
			b.Rules = append(b.Rules, engine.Rule{Verdict: engine.Deny, Rule: rule, Role: name})
		}
		// A role that permits nothing contributes no pipe list, or a deny-only
		// role would widen every other role's allowlist to the default.
		if len(r.Permit) > 0 {
			list := r.Pipe
			if list == nil {
				list = DefaultPipe
			}
			for _, rule := range list {
				pipe[rule] = true
			}
		}
		for _, rule := range slices.Concat(r.Permit, r.Deny, r.Pipe) {
			terms, _ := engine.ParseRule(rule)
			for _, t := range terms {
				if t.Kind != engine.Class {
					continue
				}
				patterns, ok := dialect.EntityClasses[t.Text]
				if !ok {
					// A class the platform does not define would silently never
					// match — a deny that does nothing — so it is an error, and
					// at load, not at a mint (spec §4, §8).
					return engine.Blob{}, nil, fmt.Errorf("role %q names @%s, which %s does not define", name,
						t.Text, platformName(d.Platform))
				}
				b.Classes[t.Text] = patterns
			}
		}
	}
	for rule := range pipe {
		b.Pipe = append(b.Pipe, rule)
	}
	sort.Strings(b.Pipe)
	// Rules take Encode's canonical form and order too, so the blob explain and a test
	// read is the one the hash names, whatever order the file lists roles and
	// rules in. Evaluation is order-independent (spec §5.4).
	for i := range b.Rules {
		b.Rules[i].Rule = engine.CanonicalRule(b.Rules[i].Rule)
	}
	slices.SortFunc(b.Rules, func(x, y engine.Rule) int {
		return strings.Compare(x.Verdict+"\x00"+x.Rule+"\x00"+x.Role, y.Verdict+"\x00"+y.Rule+"\x00"+y.Role)
	})
	b.Rules = slices.Compact(b.Rules)
	attrs, err := p.layerAttributes(c, d.Platform, dialect)
	if err != nil {
		return engine.Blob{}, nil, err
	}
	for _, a := range attrs {
		b.Attributes = append(b.Attributes, a.Attribute)
	}
	// The daemon's twin of the joint check below: it refuses a reply the
	// device would refuse, under the adapter this policy merged.
	if len(dialect.AcceptedAttributes) > 0 {
		b.AcceptedAttributes = slices.Clone(dialect.AcceptedAttributes)
		slices.Sort(b.AcceptedAttributes)
		b.AcceptedAttributes = slices.Compact(b.AcceptedAttributes)
	}
	return b, attrs, nil
}

func platformName(name string) string {
	if name == "" {
		return "a device with no platform"
	}
	return name
}

// layerAttributes applies spec §6's layering, platform → role → grant, most
// specific winning on a duplicate attribute name and every override recorded.
// Within one layer, sources are taken in name order — roles by name, grants by
// scope — so which one wins cannot depend on a file's layout.
func (p *Policy) layerAttributes(c composition, platformName string, dialect platform.Dialect) ([]AttributeSource, error) {
	var out []AttributeSource
	index := map[string]int{}
	put := func(a, source string) {
		name := engine.AttributeName(a)
		if i, ok := index[name]; ok {
			prev := out[i]
			out[i] = AttributeSource{Attribute: a, Source: source,
				Shadows: append(prev.Shadows, prev.Attribute+" ("+prev.Source+")")}
			return
		}
		index[name] = len(out)
		out = append(out, AttributeSource{Attribute: a, Source: source})
	}
	if c.level != "" {
		attrs, rendered, ok := p.render(dialect, c.level)
		if !ok {
			return nil, fmt.Errorf("level %s has no rendering on %s and no parent that has one (spec §6)",
				c.level, platformName)
		}
		for _, a := range attrs {
			put(a, "platform "+platformName+", level "+rendered)
		}
	}
	for _, name := range c.roles {
		attrs := p.roles[name].Attributes
		for _, a := range slices.Concat(attrs["all"], attrs[platformName]) {
			put(a, "role "+name)
		}
	}
	for _, g := range c.grants {
		for _, a := range slices.Concat(g.Attributes["all"], g.Attributes[platformName]) {
			put(a, "grant "+g.Scope+" ["+strings.Join(g.Roles, " ")+"]")
		}
	}
	return out, nil
}

// render follows a level's parent chain to the first level the platform maps
// (spec §6, `parent:`), returning its attributes and which level rendered.
func (p *Policy) render(dialect platform.Dialect, level string) ([]string, string, bool) {
	for l := level; l != ""; l = p.parents[l] {
		if attrs, ok := dialect.Render(l); ok {
			return attrs, l, true
		}
	}
	return nil, "", false
}

// ErrDeviceQuarantined is device_quarantined: the device failed a joint
// policy-and-inventory check at load, so nothing is minted for it (spec §10,
// §13 decision 20). The wrapped message names the cause.
var ErrDeviceQuarantined = errors.New("policy: the device is quarantined")

// Quarantine is one device a joint check fails on, now or once a grant
// expires, and every entry: which subject's composition fails, from when,
// until when, and why (spec §10). Quarantine is time-scoped: a check that
// will fail after an expiry has not failed yet, so access that works today
// keeps working until then.
type Quarantine struct {
	Device, Platform string
	// Entries are in subject order, then time order.
	Entries []QuarantineEntry
}

// QuarantineEntry is one subject's failing composition on a device, over
// [From, Until). A load-time failure has From the load's present and Lapsing
// empty, and holds for any time asked; one an expiry brings on has From that
// instant and Lapsing the grants whose expiry it is. Until is the next expiry
// that clears it, zero when none does.
type QuarantineEntry struct {
	From, Until time.Time
	Lapsing     string
	// Cause names the subject and the failure.
	Cause string
}

// Current reports whether the entry quarantines the device at now.
func (e QuarantineEntry) Current(now time.Time) bool {
	return (e.Lapsing == "" || !now.Before(e.From)) && (e.Until.IsZero() || now.Before(e.Until))
}

// Message is the entry as the start-up log and explain state it at now.
func (e QuarantineEntry) Message(now time.Time) string {
	if e.Current(now) {
		return "quarantined: " + e.Cause
	}
	return fmt.Sprintf("will be quarantined from %s, when %s expires: %s", decision.FormatTime(e.From), e.Lapsing,
		e.Cause)
}

// Quarantines lists every device with an entry current or scheduled at now,
// by name, each carrying only those entries: the start-up log's list and the
// quarantine gauge's source.
func (p *Policy) Quarantines(now time.Time) []Quarantine {
	var out []Quarantine
	for _, name := range sortedKeys(p.quarantine) {
		q := p.quarantine[name]
		var entries []QuarantineEntry
		for _, e := range q.Entries {
			if e.Current(now) || now.Before(e.From) {
				entries = append(entries, e)
			}
		}
		if len(entries) > 0 {
			out = append(out, Quarantine{Device: q.Device, Platform: q.Platform, Entries: entries})
		}
	}
	return out
}

// Quarantined reports whether device is quarantined at now, and its first
// current cause: what the daemon and the broker ask before a mint or a reply.
func (p *Policy) Quarantined(device string, now time.Time) (cause string, ok bool) {
	if q, found := p.quarantine[device]; found {
		for _, e := range q.Entries {
			if e.Current(now) {
				return e.Cause, true
			}
		}
	}
	return "", false
}

// quarantined is Resolve's refusal for a device quarantined at now.
func (p *Policy) quarantined(d admission.Device, now time.Time) error {
	if cause, ok := p.Quarantined(d.Name, now); ok {
		return fmt.Errorf("%w: %s", ErrDeviceQuarantined, cause)
	}
	return nil
}

// checkDevices runs every subject's composition on every device in the
// inventory, and quarantines a device where one would not compile or would
// contradict itself: a class its platform does not define, a level it cannot
// render, a ceiling it cannot number, a landing level above the ceiling, a
// blob the engine refuses, and `enable: auto` where its enable exchange does
// not carry the principal (spec §4, §5.6, §6, §7). A composition changes only
// when a grant expires, so each is checked at the load's present and again at
// every later expiry, and a failure is quarantined over the span it holds: a
// device that will fail once a grant lapses is scheduled for then, not
// quarantined now. A quarantined device is skipped — refused at mint, closed
// without a reply by the daemon — and the rest of the fleet loads (spec §10,
// §13 decision 20); refusing the policy instead would take every device down
// for one. A check no platform could pass is the policy's own error and
// refused at load (checkClasses, numberedAnywhere). Plan 6 moves quarantine
// into the bundle the inventory service publishes.
func (p *Policy) checkDevices() {
	p.quarantine = map[string]*Quarantine{}
	now := p.env.Now
	if now.IsZero() {
		now = time.Now()
	}
	for _, d := range p.env.Devices {
		for _, name := range sortedKeys(p.subs) {
			entries := p.checkDevice(p.subs[name], d, now)
			if len(entries) == 0 {
				continue
			}
			q, ok := p.quarantine[d.Name]
			if !ok {
				q = &Quarantine{Device: d.Name, Platform: d.Platform}
				p.quarantine[d.Name] = q
			}
			q.Entries = append(q.Entries, entries...)
		}
	}
}

// checkDevice is one subject's joint checks on one device, at now and at
// every later instant one of its grants expires, as the spans each failure
// holds over; none is none failed.
func (p *Policy) checkDevice(sub *Subject, d admission.Device, now time.Time) []QuarantineEntry {
	lapsing := map[time.Time][]string{}
	instants := []time.Time{now}
	for _, g := range p.grants {
		if g.Subject != sub.Name || !g.Expires.After(now) {
			continue
		}
		if _, ok := lapsing[g.Expires]; !ok {
			instants = append(instants, g.Expires)
		}
		lapsing[g.Expires] = append(lapsing[g.Expires], "grant "+g.Scope+" ["+strings.Join(g.Roles, " ")+"]")
	}
	sort.Slice(instants[1:], func(i, j int) bool { return instants[1+i].Before(instants[1+j]) })
	var out []QuarantineEntry
	open := false // whether the last entry is still failing
	for _, at := range instants {
		cause := p.checkDeviceAt(sub, d, at)
		if cause != "" {
			cause = fmt.Sprintf("subject %q: %s", sub.Name, cause)
		}
		if open && cause == out[len(out)-1].Cause {
			continue
		}
		if open {
			out[len(out)-1].Until = at
		}
		open = cause != ""
		if open {
			out = append(out, QuarantineEntry{From: at, Lapsing: strings.Join(lapsing[at], " and "), Cause: cause})
		}
	}
	return out
}

// checkDeviceAt is one subject's joint checks on one device at one instant.
func (p *Policy) checkDeviceAt(sub *Subject, d admission.Device, at time.Time) string {
	res, err := p.resolve(sub, d, at)
	if errors.Is(err, ErrNoGrants) {
		return ""
	}
	if err != nil {
		return err.Error()
	}
	if _, _, err := engine.Encode(res.Blob); err != nil {
		return fmt.Sprintf("its compiled blob for %s is refused, so no mint could carry it: %v",
			platformName(d.Platform), err)
	}
	// The ceiling caps the level whatever the platform numbers them: where
	// operator and admin both number 15 (decision 23), a numeric check alone
	// would let an admin role capped at operator through (spec §7).
	if res.HasCeiling && res.Level != "" && p.levelIndex(res.Level) > p.levelIndex(res.Ceiling) {
		return fmt.Sprintf("on %s its roles land it at %s, above its grants' max_privilege %s in "+
			"privilege_levels: the ceiling caps the level on every platform, however %s numbers the two; raise "+
			"max_privilege or lower the role", d.Platform, res.Level, res.Ceiling, d.Platform)
	}
	if res.HasCeiling && res.Level != "" {
		if landing, ok := p.privLvl(p.dialect(d.Platform), res.Level); ok && landing > res.MaxPrivilege {
			return fmt.Sprintf("on %s its roles land it at %s (priv-lvl %d), above its grants' max_privilege %s "+
				"(%d): the device would be told %d while port49 holds the session at %d, and every command would "+
				"be denied privilege_exceeded; raise max_privilege or lower the role", d.Platform, res.Level, landing,
				res.Ceiling, res.MaxPrivilege, landing, res.MaxPrivilege)
		}
	}
	if res.HasCeiling {
		// §6 layering lets a role or grant set priv-lvl over the level's
		// rendering, and the device applies what the reply says. The reply is
		// read as the daemon reads it (engine.GrantedPrivLvl), with the
		// placeholders a mint cannot know left empty.
		attrs, err := res.Blob.SessionAttributes(engine.Values{})
		if err != nil {
			attrs = res.Blob.Attributes
		}
		if sent, at, ok := engine.GrantedPrivLvl(attrs); ok && sent > res.MaxPrivilege {
			return fmt.Sprintf("on %s its session reply sends %s (%s), above its grants' max_privilege %s (%d): "+
				"the daemon refuses a session whose reply exceeds the ceiling, so every login would fail "+
				"blob_unavailable; raise max_privilege or remove the attribute", d.Platform,
				res.Attributes[at].Attribute, res.Attributes[at].Source, res.Ceiling, res.MaxPrivilege)
		}
	}
	// A platform that refuses a session for any attribute it does not take
	// is never sent one: the device would refuse every login, and on IOS-XE a
	// run of refusals stops it answering SSH for about a minute, break-glass
	// included (tests/lab/results/L18-cisco_iosxe.md). Quarantined, the
	// device is closed without a reply and falls to local at once.
	lockout := ""
	if d.Platform == "cisco_iosxe" {
		lockout = ", and a run of refusals stops it answering SSH, break-glass included " +
			"(tests/lab/results/L18-cisco_iosxe.md)"
	}
	// priv-lvl's values are closed on every platform: a device sent one it
	// cannot use refuses the session, as IOS-XE did for priv-lvl=99 rather
	// than clamp or ignore it (L18-cisco_iosxe.md, variant 7).
	for _, a := range res.Attributes {
		if engine.NotALevel(a.Attribute) {
			return fmt.Sprintf("on %s its session reply sends %s (%s), which is not a privilege level: priv-lvl "+
				"runs 0 to 15, and a device sent a value it cannot use refuses the session (IOS-XE did for "+
				"priv-lvl=99, tests/lab/results/L18-cisco_iosxe.md, variant 7)%s; fix the value", d.Platform,
				a.Attribute, a.Source, lockout)
		}
	}
	if dialect := p.dialect(d.Platform); dialect.AcceptedAttributes != nil {
		// A closed platform is sent only the levels its adapter renders: what
		// the device lets any other level run is unmeasured.
		var rendered []uint8
		for _, level := range sortedKeys(dialect.Levels) {
			if n, ok := dialect.PrivLvl(level); ok && !slices.Contains(rendered, n) {
				rendered = append(rendered, n)
			}
		}
		slices.Sort(rendered)
		for _, a := range res.Attributes {
			name := engine.AttributeName(a.Attribute)
			if !slices.Contains(dialect.AcceptedAttributes, name) {
				return fmt.Sprintf("on %s its session reply sends %s (%s), and %s takes no attribute but %s: the "+
					"device refuses the whole session for any other%s; key the attribute to the platforms that "+
					"read it", d.Platform, a.Attribute, a.Source, d.Platform, strings.Join(dialect.AcceptedAttributes, ", "),
					lockout)
			}
			if name != "priv-lvl" {
				continue
			}
			// Not a level was refused above, so the value parses.
			if n, _ := engine.PrivLvlValue(a.Attribute[len(name)+1:]); !slices.Contains(rendered, n) {
				return fmt.Sprintf("on %s its session reply sends %s (%s), and %s's adapter renders priv-lvl %s only: "+
					"what the device lets another level run is unmeasured, so it is not sent; use a level's own "+
					"rendering", d.Platform, a.Attribute, a.Source, d.Platform, levelList(rendered))
			}
		}
	}
	if sub.Enable == "auto" {
		if eu := p.env.EnableUsernames[d.Platform]; eu != "" && eu != platform.EnablePrincipal {
			return fmt.Sprintf("enable: auto reaches this device, whose platform %s does not put the operator's "+
				"own username on the enable exchange; use token or none (spec §5.6, \"Why enable: auto is "+
				"restricted\")", d.Platform)
		}
	}
	return ""
}

// levelList reads levels as a sentence does: "1, 7 and 15".
func levelList(levels []uint8) string {
	s := make([]string, len(levels))
	for i, n := range levels {
		s[i] = strconv.Itoa(int(n))
	}
	if len(s) < 2 {
		return strings.Join(s, "")
	}
	return strings.Join(s[:len(s)-1], ", ") + " and " + s[len(s)-1]
}
