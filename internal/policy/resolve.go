package policy

import (
	"errors"
	"fmt"
	"slices"
	"sort"
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
	if err := p.quarantined(d); err != nil {
		return Resolution{}, err
	}
	return p.resolve(p.subs[name], d, now)
}

// ResolveSubject is Resolve for a subject named directly, as the offline
// tools name them: a group subject has no identity to resolve by until plan 7
// reads the directory.
func (p *Policy) ResolveSubject(subject string, d admission.Device, now time.Time) (Resolution, error) {
	sub, ok := p.subs[subject]
	if !ok {
		return Resolution{}, fmt.Errorf("policy: subject %q is not declared", subject)
	}
	if err := p.quarantined(d); err != nil {
		return Resolution{}, err
	}
	return p.resolve(sub, d, now)
}

func (p *Policy) resolve(sub *Subject, d admission.Device, now time.Time) (Resolution, error) {
	c := p.compose(sub, d, now)
	if len(c.grants) == 0 {
		return Resolution{}, ErrNoGrants
	}
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
		Normalize: engine.Normalize{PipeToken: dialect.PipeToken, PipeAuthorized: dialect.PipeAuthorized,
			StripCR: dialect.StripCR, ExpandsAbbreviations: dialect.ExpandsAbbreviations},
		Classes: map[string][]string{}}
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
	// Rules take Encode's canonical order too, so the blob explain and a test
	// read is the one the hash names, whatever order the file lists roles and
	// rules in. Evaluation is order-independent (spec §5.4).
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

// Quarantine is one device that failed a joint check at load, and every
// cause: the subjects whose composition on it would not compile or would
// contradict itself.
type Quarantine struct {
	Device, Platform string
	Causes           []string
}

// Quarantined lists the quarantined devices by name.
func (p *Policy) Quarantined() []Quarantine {
	out := make([]Quarantine, 0, len(p.quarantine))
	for _, q := range p.quarantine {
		out = append(out, *q)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Device < out[j].Device })
	return out
}

// quarantined is Resolve's refusal for a quarantined device, naming its first
// cause.
func (p *Policy) quarantined(d admission.Device) error {
	if q, ok := p.quarantine[d.Name]; ok {
		return fmt.Errorf("%w: %s", ErrDeviceQuarantined, q.Causes[0])
	}
	return nil
}

// checkDevices runs every subject's composition on every device in the
// inventory, and quarantines a device where one would not compile or would
// contradict itself: a class its platform does not define, a level it cannot
// render, a ceiling it cannot number, a landing level above the ceiling, a
// blob the engine refuses, and `enable: auto` where its enable exchange does
// not carry the principal (spec §4, §5.6, §6, §7). A composition changes only
// when a grant expires, so each is checked now and again at every later
// expiry: a device that fails once a grant lapses is quarantined from the
// start, not left to fail at a mint. A quarantined device is skipped —
// refused at mint, closed without a reply by the daemon — and the rest of the
// fleet loads (spec §10, §13 decision 20); refusing the policy instead would
// take every device down for one. A check no platform could pass is the
// policy's own error and refused at load (checkClasses, numberedAnywhere).
// Plan 6 moves quarantine into the bundle the inventory service publishes.
func (p *Policy) checkDevices() {
	p.quarantine = map[string]*Quarantine{}
	now := p.env.Now
	if now.IsZero() {
		now = time.Now()
	}
	names := make([]string, 0, len(p.subs))
	for name := range p.subs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, d := range p.env.Devices {
		for _, name := range names {
			if cause := p.checkDevice(p.subs[name], d, now); cause != "" {
				q, ok := p.quarantine[d.Name]
				if !ok {
					q = &Quarantine{Device: d.Name, Platform: d.Platform}
					p.quarantine[d.Name] = q
				}
				q.Causes = append(q.Causes, fmt.Sprintf("subject %q: %s", name, cause))
			}
		}
	}
}

// checkDevice is one subject's joint checks on one device, at now and at
// every later instant one of its grants expires; "" is none failed. A cause
// found after an expiry names the instant and the grants that lapse at it.
func (p *Policy) checkDevice(sub *Subject, d admission.Device, now time.Time) string {
	if cause := p.checkDeviceAt(sub, d, now); cause != "" {
		return cause
	}
	lapsing := map[time.Time][]string{}
	var instants []time.Time
	for _, g := range p.grants {
		if g.Subject != sub.Name || !g.Expires.After(now) {
			continue
		}
		if _, ok := lapsing[g.Expires]; !ok {
			instants = append(instants, g.Expires)
		}
		lapsing[g.Expires] = append(lapsing[g.Expires], "grant "+g.Scope+" ["+strings.Join(g.Roles, " ")+"]")
	}
	sort.Slice(instants, func(i, j int) bool { return instants[i].Before(instants[j]) })
	for _, at := range instants {
		if cause := p.checkDeviceAt(sub, d, at); cause != "" {
			return fmt.Sprintf("from %s, when %s expires: %s", decision.FormatTime(at),
				strings.Join(lapsing[at], " and "), cause)
		}
	}
	return ""
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
	if res.HasCeiling && res.Level != "" {
		if landing, ok := p.privLvl(p.dialect(d.Platform), res.Level); ok && landing > res.MaxPrivilege {
			return fmt.Sprintf("on %s its roles land it at %s (priv-lvl %d), above its grants' max_privilege %s "+
				"(%d): the device would be told %d while port49 holds the session at %d, and every command would "+
				"be denied privilege_exceeded; raise max_privilege or lower the role", d.Platform, res.Level, landing,
				res.Ceiling, res.MaxPrivilege, landing, res.MaxPrivilege)
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
