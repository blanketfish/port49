package policy

import (
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/projection"
)

// Finding is something CI reports about a policy that loads: not an error,
// but a fact a reviewer should see stated rather than discover (spec §5.5,
// §6, §12). `port49 policy test` prints them.
type Finding struct {
	Kind    string
	Message string
}

// The finding kinds.
const (
	FindingAttachedPermit      = "attached_permit"
	FindingGrantlessSubject    = "grantless_subject"
	FindingAPIRights           = "api_rights"
	FindingGroupSubject        = "group_subject"
	FindingMandatoryAttribute  = "mandatory_attribute"
	FindingAttributeShadowed   = "attribute_shadowed"
	FindingIncomparableVersion = "incomparable_version"
	FindingDenyWidened         = "deny_widened"
	FindingPermitJoinedName    = "permit_joined_name"
	FindingNoTests             = "no_tests"
	FindingCeilingIndistinct   = "ceiling_indistinct"
	FindingAcknowledgeStale    = "acknowledge_stale"
	FindingPlatformOverride    = "platform_override_redundant"
	FindingRuleSecretLiteral   = "rule_secret_literal"
	// FindingDeviceConfigSecretLiteral is a `platforms:` block's device_config
	// line carrying a value redaction hides (spec §5.8).
	FindingDeviceConfigSecretLiteral = "device_config_secret_literal"
	// FindingProjection is how a composition's rules render on a projected
	// platform: the shape, the bits, what each regex carries, and where the
	// device is narrower than port49 (spec §8).
	FindingProjection = "projection"
	// FindingProjectionOverflow is a reply attribute past RFC 8907's length:
	// the subject gets the fail-closed reply, and where the attribute is
	// deny-commands the finding prints the class line that would carry the
	// denies on the device instead (spec §8). Never for allow-commands: a
	// class allow runs for every subject at that template, past their own
	// denies (L11). It fails `policy test`.
	FindingProjectionOverflow = "projection_overflow"
	// FindingProjectionRefused is a composition a projected platform cannot
	// be told faithfully, naming the subject, the devices and the reason: the
	// subject gets the fail-closed reply there and everyone else keeps
	// theirs (spec §13 decision 26). It fails `policy test`, as spec §8's
	// "CI MUST refuse the policy" requires.
	FindingProjectionRefused = "projection_refused"
	// FindingUnenforcedRules is a subject's command rules on a platform that
	// neither asks port49 about a command nor has them projected into its
	// session reply: they decide nothing there (spec §9, "CI").
	FindingUnenforcedRules = "unenforced_rules"
	// FindingPinAbsent is a scope pinning a name the inventory lacks: it
	// selects nothing there. A warning, not a failure, since a device may be
	// pinned before it is onboarded (spec §10).
	FindingPinAbsent = "pin_absent"
)

// Lint computes the findings at now, ordered by kind and then message so two
// runs over one policy print the same report. A composition is read at now
// and at every later grant expiry, as the shadowed-deny report reads it, so a
// grant that has lapsed reports nothing.
func (p *Policy) Lint(now time.Time) []Finding {
	var out []Finding
	add := func(kind, format string, args ...any) {
		out = append(out, Finding{Kind: kind, Message: fmt.Sprintf(format, args...)})
	}
	for name, s := range p.scopes {
		for _, domain := range []string{"humans", "machines"} {
			for _, r := range s.Attached[domain] {
				if len(p.roles[r].Permit) > 0 {
					add(FindingAttachedPermit, "scope %q attaches role %q to every %s grant that reaches its "+
						"devices, and the role carries a permit (spec §5.5): a fleet-wide deny is routine, a "+
						"fleet-wide permit rarely is", name, r, strings.TrimSuffix(domain, "s"))
				}
			}
		}
	}
	for name, sub := range p.subs {
		if len(p.Grants(name)) == 0 {
			add(FindingGrantlessSubject, "subject %q has no grant and matches nothing; remove the block (spec §12)", name)
		}
		if len(sub.API) > 0 {
			add(FindingAPIRights, "subject %q holds api: [%s], authority over other people's sessions (spec §2)",
				name, strings.Join(sub.API, " "))
		}
		if sub.Group != "" {
			add(FindingGroupSubject, "subject %q is a group: the broker matches a principal to a group through the "+
				"directory, which is plan 7's, so until then it mints for no one; explain and policy tests "+
				"evaluate it by name", name)
		}
	}
	for name, r := range p.roles {
		for key, list := range r.Attributes {
			for _, a := range list {
				if engine.Mandatory(a) {
					add(FindingMandatoryAttribute, "role %q sends %s mandatory on %s: a device that cannot parse "+
						"it refuses the whole session (spec §6); write it with `*` unless the device needs `=`",
						name, a, key)
				}
			}
		}
	}
	for _, g := range p.grants {
		for key, list := range g.Attributes {
			for _, a := range list {
				if engine.Mandatory(a) {
					add(FindingMandatoryAttribute, "the grant of %s on %s sends %s mandatory on %s: a device that "+
						"cannot parse it refuses the whole session (spec §6)", g.Subject, g.Scope, a, key)
				}
			}
		}
	}
	seen := map[string]bool{}
	instants := p.expiryInstants(now)
	for name, sub := range p.subs {
		for _, d := range p.env.Devices {
			for _, at := range instants {
				res, err := p.resolve(sub, d, at)
				if err != nil {
					// No grant here means nothing to shadow, and any other
					// error quarantines the device, which Quarantined reports.
					continue
				}
				for _, a := range res.Attributes {
					for _, shadowed := range a.Shadows {
						msg := fmt.Sprintf("subject %q on %s: %s (%s) shadows %s", name, d.Platform, a.Attribute,
							a.Source, shadowed)
						if !seen[msg] {
							seen[msg] = true
							add(FindingAttributeShadowed, "%s", msg)
						}
					}
				}
			}
		}
	}
	for name, s := range p.scopes {
		for _, d := range p.env.Devices {
			if ok, byIncomparable := s.selects(d); ok && byIncomparable {
				add(FindingIncomparableVersion, "scope %q includes %s because its version could not be compared "+
					"(%s); name the version explicitly, match it by regex, or exclude it by another attribute "+
					"(spec §5.5)", name, d.Name, s.comparedValues(d))
			}
		}
	}
	for name, s := range p.scopes {
		for _, pin := range s.Match["name"].Equal {
			if !slices.ContainsFunc(p.env.Devices, func(d admission.Device) bool { return d.Name == pin }) {
				add(FindingPinAbsent, "scope %q pins %q, which is not in the inventory, so it selects nothing there: "+
					"a warning, not a failure, since a device may be pinned before it is onboarded; if the name is a "+
					"typo, a deny the scope carries never applies (spec §10)", name, pin)
			}
		}
	}
	for _, f := range p.indistinctCeilings() {
		add(FindingCeilingIndistinct, "%s", f)
	}
	secrets := p.HiddenValues()
	for _, a := range p.acked {
		if a.Role != "" && p.hasDeny(a.Rule) {
			rule := platform.QuoteShown(secrets, a.Rule)
			add(FindingAcknowledgeStale, "acknowledge: %s %s: the policy still denies %s, so the entry removed nothing "+
				"and acknowledges nothing; delete it (spec §12)", a.Role, rule, rule)
		}
	}
	out = append(out, p.redundantOverrides()...)
	out = append(out, p.Projections(now)...)
	out = append(out, p.UnenforcedRules(now)...)
	out = append(out, p.intersections(now)...)
	if len(p.tests) == 0 {
		add(FindingNoTests, "the policy has no tests: nothing in it acknowledges a shadowed deny, an expansion or "+
			"a privilege raise, so the gates fail on the first one; add tests (spec §12, \"Policy tests\")")
	}
	out = append(out, p.WidenedDenies()...)
	out = append(out, p.JoinedNamePermits()...)
	out = append(out, p.RuleSecretLiterals()...)
	out = append(out, p.DeviceConfigSecretLiterals()...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Message < out[j].Message
	})
	return out
}

// comparedValues renders the device's values for every compared key against
// the bound, e.g. `os_version 21.4X75-D40 lt 21.4R3-S5`.
func (s *Scope) comparedValues(d admission.Device) string {
	var parts []string
	keys := make([]string, 0, len(s.Match))
	for k := range s.Match {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		ops := make([]string, 0, len(s.Match[k].Cmp))
		for op := range s.Match[k].Cmp {
			if op != "re" {
				ops = append(ops, op)
			}
		}
		slices.Sort(ops)
		for _, op := range ops {
			parts = append(parts, fmt.Sprintf("%s %s %s %s", k, d.Attributes[k], op, s.Match[k].Cmp[op]))
		}
	}
	return strings.Join(parts, "; ")
}

// WidenedDenies names every deny term that matches any argument on a platform
// in the inventory, because the platform may send what was typed and the
// term's abbreviations cannot be read (spec §3 rule 4). It over-denies rather
// than refuse the device, so the operator is told here, and by port49d at
// start, which term and why.
func (p *Policy) WidenedDenies() []Finding {
	platforms := map[string]bool{}
	for _, d := range p.env.Devices {
		platforms[d.Platform] = true
	}
	secrets := p.HiddenValues()
	var out []Finding
	for _, name := range sortedKeys(p.roles) {
		for _, rule := range p.roles[name].Deny {
			for _, plat := range sortedKeys(platforms) {
				for _, why := range engine.WidenedToAny(rule, p.dialect(plat).EntityClasses, p.normalizeFor(plat)) {
					out = append(out, Finding{Kind: FindingDenyWidened, Message: fmt.Sprintf(
						"role %q: deny %s on %s: %s", name, platform.QuoteShown(secrets, rule), plat, why)})
				}
			}
		}
	}
	return out
}

// JoinedNamePermits names every permit word written as an interface name and
// its index joined, on each platform in the inventory that sends the two
// apart: IOS-XE sends a typed `Gi1` as `GigabitEthernet`, `1`
// (tests/lab/results/L21-cisco_iosxe.md), and a permit matches only as
// written (spec §3 rule 5), so the word never matches there. It is reported
// here, and by port49d at start, rather than discovered as a denial.
func (p *Policy) JoinedNamePermits() []Finding {
	platforms := map[string]bool{}
	for _, d := range p.env.Devices {
		if p.dialect(d.Platform).SplitsInterfaceNames {
			platforms[d.Platform] = true
		}
	}
	secrets := p.HiddenValues()
	var out []Finding
	for _, name := range sortedKeys(p.roles) {
		for _, rule := range p.roles[name].Permit {
			terms, err := engine.ParseRule(rule)
			if err != nil {
				continue
			}
			// A word redaction hides, in this rule or any other, is never
			// named, nor split into the fix: rule_secret_literal reports the
			// rule that carries it, and `HUNTER 2` would print the secret
			// past any writer (spec §5.8).
			for _, plat := range sortedKeys(platforms) {
				for _, t := range terms {
					if hidden(secrets, t.Text) {
						continue
					}
					if head, index, ok := engine.SplitName(t.Text); ok && t.Kind == engine.Word {
						out = append(out, Finding{Kind: FindingPermitJoinedName, Message: fmt.Sprintf(
							"role %q: permit %s on %s: `%s` never matches on %s, which sends it as two arguments "+
								"(tests/lab/results/L21-cisco_iosxe.md); write `%s %s`", name,
							platform.QuoteShown(secrets, rule), plat, t.Text, plat,
							head, index)})
					}
				}
			}
		}
	}
	return out
}

// Redactions is every pattern that applies anywhere under this policy: the
// built-in ones of every platform and every `platforms:` block's. It redacts
// text that belongs to no one platform — a report, a line quoting a rule —
// so it errs toward hiding (spec §5.8).
func (p *Policy) Redactions() []platform.Redaction {
	all := platform.AllRedactions()
	for _, name := range sortedKeys(p.adapters) {
		all = append(all, p.adapters[name].Redact...)
	}
	return all
}

// HiddenValues is every value Redactions hides in a role's rule: what a
// report's writer redacts wherever a line prints it, since a finding may
// derive text from a rule, a word it names or a fix it suggests, beside the
// rule's quoted form (platform.RedactValues; spec §5.8).
func (p *Policy) HiddenValues() []string {
	p.hiddenOnce.Do(func() { p.hiddenValues = p.hiddenValuesOnce() })
	return slices.Clone(p.hiddenValues)
}

// hiddenValuesOnce is HiddenValues worked out: every pattern over every rule.
func (p *Policy) hiddenValuesOnce() []string {
	patterns := p.Redactions()
	var out []string
	for _, name := range sortedKeys(p.roles) {
		r := p.roles[name]
		for _, rule := range slices.Concat(r.Permit, r.Deny, r.Pipe) {
			for _, v := range platform.HiddenValues(patterns, strings.Fields(rule)) {
				if !slices.Contains(out, v) {
					out = append(out, v)
				}
			}
		}
	}
	return out
}

// hidden reports whether word is, in any letter case, one of values, the
// values a redaction hides (HiddenValues): text derived from it, split,
// joined or re-cased, is left out where it is made, since no writer
// recognizes a rewritten secret (spec §5.8).
func hidden(values []string, word string) bool {
	return slices.ContainsFunc(values, func(v string) bool { return strings.EqualFold(v, word) })
}

// SecretClasses is every entity class a role's rule names where a value is
// redacted, by every pattern the policy knows (Redactions): such a class
// holds those values, `snmp-server community @bad **` bad communities, and
// what prints its patterns prints them redacted, as the blob event does
// (spec §5.8).
func (p *Policy) SecretClasses() map[string]bool {
	patterns, out := p.Redactions(), map[string]bool{}
	for _, name := range sortedKeys(p.roles) {
		r := p.roles[name]
		for _, rule := range slices.Concat(r.Permit, r.Deny, r.Pipe) {
			orig := strings.Fields(rule)
			words, _ := platform.RedactRule(patterns, orig)
			for k, w := range words {
				if w == platform.Redacted && strings.HasPrefix(orig[k], "@") {
					out[orig[k][1:]] = true
				}
			}
		}
	}
	return out
}

// RuleSecretLiterals names every rule with a value the redaction patterns of
// a platform in the inventory hide (spec §5.8): the rule loads — a deny on a
// known-bad community is legitimate — but wherever it is echoed, a record's
// matched rules, a denial's server_msg, the blob event, the value reads
// «redacted». The rule is named in its redacted form, because this report
// is printed by port49d at start, to a log like any other.
func (p *Policy) RuleSecretLiterals() []Finding {
	platforms := map[string]bool{}
	for _, d := range p.env.Devices {
		platforms[d.Platform] = true
	}
	if len(platforms) == 0 {
		platforms["default"] = true
	}
	secrets := p.HiddenValues()
	var out []Finding
	for _, name := range sortedKeys(p.roles) {
		r := p.roles[name]
		for _, verdict := range []string{"deny", "permit", "pipe permit"} {
			rules := r.Deny
			switch verdict {
			case "permit":
				rules = r.Permit
			case "pipe permit":
				rules = r.Pipe
			}
			for _, rule := range rules {
				var on []string
				var shown []string
				for _, plat := range sortedKeys(platforms) {
					patterns := append(platform.Redactions(p.WirePlatform(plat)), p.dialect(plat).Redact...)
					if words, ok := platform.RedactRule(patterns, strings.Fields(rule)); ok {
						on, shown = append(on, plat), words
					}
				}
				if len(on) > 0 {
					out = append(out, Finding{Kind: FindingRuleSecretLiteral, Message: fmt.Sprintf(
						"role %q: %s %s carries a value redaction hides on %s: the value is in the policy file, "+
							"and every log, record and server_msg that echoes the rule shows it redacted",
						name, verdict, platform.QuoteShown(secrets, strings.Join(shown, " ")), strings.Join(on, ", "))})
				}
			}
		}
	}
	return out
}

// DeviceConfigSecretLiterals names every device_config line a `platforms:`
// block writes with a value a redaction pattern hides (spec §5.8): an
// operator may put a line such as `snmp-server community X ro` in the
// configuration a device is held to, and it loads, but `port49 platform show`
// and `devices check-config` print it «redacted», so the operator is told the
// value lives in the policy file. The line is named by its key and index, in
// its redacted form, by every pattern that applies under the policy; a line a
// set ships is lab text and never reported (platform.RedactConfigLine). A
// block's config check whose match carries such a value is reported the same
// way.
func (p *Policy) DeviceConfigSecretLiterals() []Finding {
	patterns, secrets := p.Redactions(), p.HiddenValues()
	var out []Finding
	for _, name := range sortedKeys(p.overrides) {
		if checks := p.overrides[name].ConfigChecks; checks != nil {
			// A check's says is prose, redacted wherever it is printed and
			// not reported: ordinary wording, "falls back to a local secret",
			// would trip it.
			for i, c := range *checks {
				if platform.ShippedConfigMatch(c.Match) {
					continue
				}
				if shown := platform.RedactProse(patterns, c.Match); shown != c.Match {
					out = append(out, Finding{Kind: FindingDeviceConfigSecretLiteral, Message: fmt.Sprintf(
						"platforms.%s.config_checks[%d].match %s carries a value redaction hides: the value is in the "+
							"policy file, and platform show and export print the check redacted", name, i,
						platform.QuoteShown(secrets, shown))})
				}
			}
		}
		lines := p.overrides[name].DeviceConfig
		if lines == nil {
			continue
		}
		for i, line := range *lines {
			if shown := platform.RedactConfigLine(patterns, line); strings.Contains(shown, platform.Redacted) {
				out = append(out, Finding{Kind: FindingDeviceConfigSecretLiteral, Message: fmt.Sprintf(
					"platforms.%s.device_config[%d] %s carries a value redaction hides: the value is in the policy "+
						"file, and platform show and devices check-config print the line redacted", name, i,
					platform.QuoteShown(secrets, shown))})
			}
		}
	}
	return out
}

// indistinctCeilings names each grant ceiling that numbers the same as a
// higher level on a platform in the inventory (spec §7): there `enable` can
// reach that level's device privilege under it, and only port49's command
// rules separate the two. One line per ceiling and platform, in order.
func (p *Policy) indistinctCeilings() []string {
	var out []string
	seen := map[string]bool{}
	platforms := map[string]bool{}
	for _, d := range p.env.Devices {
		if d.Platform != "" {
			platforms[d.Platform] = true
		}
	}
	for _, g := range p.grants {
		if g.MaxPrivilege == "" {
			continue
		}
		for _, name := range sortedKeys(platforms) {
			if seen[g.MaxPrivilege+"\x00"+name] {
				continue
			}
			seen[g.MaxPrivilege+"\x00"+name] = true
			d := p.dialect(name)
			n, ok := p.privLvl(d, g.MaxPrivilege)
			if !ok {
				continue
			}
			for _, higher := range p.levels[p.levelIndex(g.MaxPrivilege)+1:] {
				if m, ok := p.privLvl(d, higher); ok && m == n {
					out = append(out, fmt.Sprintf("max_privilege: %s does not limit device privilege on %s: it "+
						"numbers %d, as %s does; port49's command rules are the only fence", g.MaxPrivilege, name, n,
						higher))
					break
				}
			}
		}
	}
	return out
}

// redundantOverrides names every key a `platforms:` block sets to what the
// pinned set already says (spec §8, "Knowing what is shipped"): an override
// that matches the built-in can be removed, and left in place it would
// silently pin the old value when a later set improves it.
func (p *Policy) redundantOverrides() []Finding {
	var out []Finding
	builtin, ok := p.builtinSet(p.set)
	for _, name := range sortedKeys(p.overrides) {
		b := p.overrides[name]
		base, shipped := builtin[name]
		if !ok || !shipped || b.Replace || b.BasedOn != "" {
			continue
		}
		v := reflect.ValueOf(b.Spec)
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).IsNil() {
				continue
			}
			var one platform.Spec
			reflect.ValueOf(&one).Elem().Field(i).Set(v.Field(i))
			if reflect.DeepEqual(one.Over(base), base) {
				key := strings.Split(v.Type().Field(i).Tag.Get("yaml"), ",")[0]
				out = append(out, Finding{Kind: FindingPlatformOverride, Message: fmt.Sprintf(
					"platforms.%s.%s says what platform set %s already says; remove it, or it keeps this value when "+
						"a later set changes it", name, key, p.set)})
			}
		}
	}
	return out
}

// ShadowedBuiltIns names every key a `platforms:` block sets over a built-in
// whose built-in value differs between set from and the policy's own set:
// what `port49 platform upgrade` must say, because the upgrade changes the
// built-in and the block goes on hiding it (spec §8, override drift). The
// built-in under a block is the platform's own adapter, the one it is
// based_on, or the set's generic adapter for a block that replaces or adds a
// platform.
func (p *Policy) ShadowedBuiltIns(from string) []string {
	var out []string
	keys := platform.SpecKeys()
	for _, name := range sortedKeys(p.overrides) {
		b := p.overrides[name]
		was, ok1 := p.baseUnder(name, b, from)
		is, ok2 := p.baseUnder(name, b, p.set)
		if !ok1 || !ok2 {
			continue
		}
		set := reflect.ValueOf(b.Spec)
		old, now := reflect.ValueOf(platform.SpecOf(was)), reflect.ValueOf(platform.SpecOf(is))
		for i, key := range keys {
			if !set.Field(i).IsNil() && !reflect.DeepEqual(old.Field(i).Interface(), now.Field(i).Interface()) {
				out = append(out, "platforms."+name+"."+key)
			}
		}
	}
	return out
}

// baseUnder is the adapter set version gives the block for name to merge
// over, as buildPlatforms picks it.
func (p *Policy) baseUnder(name string, b filePlatform, version string) (platform.Dialect, bool) {
	builtin, ok := p.builtinSet(version)
	if !ok {
		return platform.Dialect{}, false
	}
	if b.BasedOn != "" {
		d, ok := builtin[b.BasedOn]
		return d, ok
	}
	if d, shipped := builtin[name]; shipped && !b.Replace {
		return d, true
	}
	return p.builtinGeneric(version)
}

// Reach is how many devices of a platform the inventory has, and how many
// subjects hold a grant on one of them at now: what a change to that
// platform's adapter affects. The generic adapter's are the devices whose
// adapter stands on it: a platform the policy has no adapter for, or one a
// block adds or replaces.
func (p *Policy) Reach(platformName string, now time.Time) (devices, subjects int) {
	holds := map[string]bool{}
	for _, d := range p.env.Devices {
		if platformName == genericPlatform && !p.onGeneric(d.Platform) ||
			platformName != genericPlatform && d.Platform != platformName {
			continue
		}
		devices++
		for name, sub := range p.subs {
			if len(p.compose(sub, d, now).grants) > 0 {
				holds[name] = true
			}
		}
	}
	return devices, len(holds)
}

// onGeneric reports whether a platform's adapter is the generic one, or a
// block merged over it.
func (p *Policy) onGeneric(name string) bool {
	if _, adapted := p.adapters[name]; !adapted {
		return true
	}
	b, written := p.overrides[name]
	if !written || b.BasedOn != "" {
		return false
	}
	builtin, _ := p.builtinSet(p.set)
	_, shipped := builtin[name]
	return b.Replace || !shipped
}

// FindingProjectionArgumentAllow is a permit whose allow is left off a
// Junos reply because the device would not match it as port49 does: it names
// a word the keyword tree does not prove a keyword, or an argument may be
// typed among its words (spec §13 decision 27). The device refuses what port49
// permits there, which fails closed, so it is a warning and does not fail
// `policy test` or `policy diff` (ProjectionRefusals does not count it).
const FindingProjectionArgumentAllow = "projection_argument_allow"

// Projections reports each composition on a projected platform (spec §8,
// "CI reports which shape each grant rendered under, the bit set it chose"):
// once per subject, platform, reply and moment, at now and at every later
// expiry of the subject's grants. A reply that holds only until a grant
// expires says until when, and one an expiry brings on says from when, as a
// scheduled quarantine does. A composition that gets the fail-closed reply
// is a projection_refused finding, or projection_overflow where a reply
// attribute is past RFC 8907's length, naming the subject, every device it
// lands on and why; both fail `policy test` (spec §13 decision 26). Each
// allow a reply leaves unsent is a projection_argument_allow warning, which
// fails nothing (decision 27). A projection finding or warning names its
// devices where it is not on every device the subject has a reply on there.
func (p *Policy) Projections(now time.Time) []Finding {
	patterns, secrets := p.Redactions(), p.HiddenValues()
	type group struct {
		kind, msg, subject, platform, moment string
		devices                              []string
	}
	var groups []*group
	index := map[string]*group{}
	for _, name := range sortedKeys(p.subs) {
		instants, lapsing := p.subjectInstants(p.subs[name], now)
		for _, d := range p.env.Devices {
			if !p.dialect(d.Platform).Projected() {
				continue
			}
			// What the device is told at each instant: a quarantine or a
			// refused mint is none, reported as one.
			replies := make([]*projection.Result, len(instants))
			for i, at := range instants {
				if res, err := p.resolve(p.subs[name], d, at); err == nil && res.Projection != nil {
					replies[i] = res.Projection
				}
			}
			// What each reply reports: its composition, and a warning for
			// each allow it leaves unsent. Each holds from the instant it
			// first appears until the first it does not.
			type item struct{ kind, msg string }
			reports := make([][]item, len(replies))
			for i, pr := range replies {
				if pr == nil {
					continue
				}
				if pr.FailClosed == "" {
					reports[i] = append(reports[i], item{FindingProjection, projectionMessage(*pr, patterns, secrets)})
				} else {
					kind, msg := refusedMessage(*pr, patterns, secrets)
					reports[i] = append(reports[i], item{kind, msg})
				}
				for _, u := range pr.Unsent {
					reports[i] = append(reports[i], item{FindingProjectionArgumentAllow, unsentMessage(u, patterns, secrets)})
				}
			}
			for i := range replies {
				for _, it := range reports[i] {
					if i > 0 && slices.Contains(reports[i-1], it) {
						continue
					}
					var moment []string
					if i > 0 {
						moment = append(moment, fmt.Sprintf("from %s, when %s expires", decision.FormatTime(instants[i]),
							lapsing[instants[i]]))
					}
					for j := i + 1; j < len(replies); j++ {
						if slices.Contains(reports[j], it) {
							continue
						}
						moment = append(moment, fmt.Sprintf("until %s, when %s expires", decision.FormatTime(instants[j]),
							lapsing[instants[j]]))
						break
					}
					key := strings.Join([]string{name, d.Platform, it.kind, strings.Join(moment, ", "), it.msg}, "\x00")
					g := index[key]
					if g == nil {
						g = &group{kind: it.kind, msg: it.msg, subject: name, platform: d.Platform,
							moment: strings.Join(moment, ", ")}
						index[key] = g
						groups = append(groups, g)
					}
					if !slices.Contains(g.devices, d.Name) {
						g.devices = append(g.devices, d.Name)
					}
				}
			}
		}
	}
	// The devices a subject has a reply on, per platform: a projection
	// finding or warning on fewer names them, so a grant to one device, or
	// one that expires on one device, never reads as every device's.
	lands := map[string]map[string]bool{}
	for _, g := range groups {
		k := g.subject + "\x00" + g.platform
		if lands[k] == nil {
			lands[k] = map[string]bool{}
		}
		for _, d := range g.devices {
			lands[k][d] = true
		}
	}
	var out []Finding
	for _, g := range groups {
		msg := fmt.Sprintf("subject %q on %s", g.subject, g.platform)
		if g.moment != "" {
			msg += ", " + g.moment
		}
		if g.kind == FindingProjection || g.kind == FindingProjectionArgumentAllow {
			msg += ":" + g.msg
		} else {
			if g.moment != "" {
				msg += ","
			}
			msg += g.msg
		}
		named := g.kind == FindingProjection || g.kind == FindingProjectionArgumentAllow
		if !named || len(g.devices) < len(lands[g.subject+"\x00"+g.platform]) {
			slices.Sort(g.devices)
			noun := "devices"
			if len(g.devices) == 1 {
				noun = "device"
			}
			msg += fmt.Sprintf("; on %d %s: %s", len(g.devices), noun, strings.Join(g.devices, ", "))
		}
		out = append(out, Finding{Kind: g.kind, Message: msg})
	}
	return out
}

// subjectInstants is now and every later instant one of sub's grants
// expires, in order, with the grants lapsing at each, named as a scheduled
// quarantine names them: the only instants at which sub's composition can
// change.
func (p *Policy) subjectInstants(sub *Subject, now time.Time) ([]time.Time, map[time.Time]string) {
	instants := []time.Time{now}
	lapsing := map[time.Time]string{}
	for _, g := range p.grants {
		if g.Subject != sub.Name || !g.Expires.After(now) {
			continue
		}
		if _, ok := lapsing[g.Expires]; ok {
			lapsing[g.Expires] += " and "
		} else {
			instants = append(instants, g.Expires)
		}
		lapsing[g.Expires] += "grant " + g.Scope + " [" + strings.Join(g.Roles, " ") + "]"
	}
	slices.SortFunc(instants[1:], func(a, b time.Time) int { return a.Compare(b) })
	return instants, lapsing
}

// ProjectionRefusals counts the findings that fail `policy test`: every
// composition that gets the fail-closed reply (spec §8, "CI MUST refuse").
func ProjectionRefusals(findings []Finding) int {
	n := 0
	for _, f := range findings {
		if f.Kind == FindingProjectionRefused || f.Kind == FindingProjectionOverflow {
			n++
		}
	}
	return n
}

// refusedMessage is a fail-closed composition's finding after its subject,
// platform and moment, which Projections writes before it, and before the
// devices, which it writes after. Every rule and value it quotes is
// redacted (spec §5.8; plan 5b pre-flight M9). The refusal's own text quotes
// only rules the secret check passed: a composition with a rule redaction
// would hide is refused as secret_rule, whose text names only the role, and
// it quotes each value another rule hides redacted (projection.Input.Hidden).
// The class line's regex writes a word re-cased or escaped, which no writer
// recognizes, so one that carries such a value prints redacted whole
// (platform.RegexShown; task 12b review I1).
func refusedMessage(pr projection.Result, patterns []platform.Redaction, secrets []string) (string, string) {
	r := pr.Refusal
	var allows []string
	for _, a := range pr.Allows {
		allows = append(allows, a.Rule)
	}
	told := "every command denied"
	if len(allows) > 0 {
		told = "every command denied but " + strings.Join(redacted(patterns, allows), "; ")
	}
	msg := fmt.Sprintf(" gets the fail-closed reply (%s): %s; it is told %s, and every other subject on those "+
		"devices keeps its reply (spec §13 decision 26)", pr.FailClosed, r.Why, told)
	if pr.FailClosed != projection.FailOverflow {
		return FindingProjectionRefused, msg
	}
	if r.Class != "" {
		msg += fmt.Sprintf("; the class line that carries the denies on the device instead, binding every subject at "+
			"that template: set system login class %s %s %s", r.Class, r.Attribute,
			platform.QuoteShown(secrets, platform.RegexShown(secrets, strings.Join(redacted(patterns,
				[]string{r.Value}), ""))))
	}
	return FindingProjectionOverflow, msg
}

// unsentMessage is an unsent allow's warning after its subject, platform
// and moment, which Projections writes before it. The rule is redacted, and
// each value another rule hides redacted before it is quoted, which would
// escape a `"` or `\` past any writer (platform.QuoteShown); Why quotes the
// rule's words the same way (projection.Input.Hidden). A rule redaction
// would hide is never among Unsent: its composition is refused as
// secret_rule first, and a fail-closed reply puts it beyond the allows.
func unsentMessage(u projection.Unsent, patterns []platform.Redaction, secrets []string) string {
	return fmt.Sprintf(" allow %s (role %q) is not sent: %s; the device refuses what port49 permits there. "+
		"Permit the whole command with `**` after its keywords, or drop the rule (spec §13 decision 27)",
		platform.QuoteShown(secrets, strings.Join(redacted(patterns, []string{u.Rule.Rule}), "")), u.Rule.Role, u.Why)
}

// projectionMessage is a composition's finding after its subject, platform
// and moment, which Projections writes before it. The commands it gives
// where the device is narrower are probes, each argument made from a value
// redaction hides printed redacted (probeShown).
func projectionMessage(pr projection.Result, patterns []platform.Redaction, secrets []string) string {
	rules := func(rs []engine.Rule) string {
		var texts []string
		for _, r := range rs {
			texts = append(texts, r.Rule)
		}
		return strings.Join(redacted(patterns, texts), "; ")
	}
	carrier := "no bits"
	switch {
	case pr.Template != "":
		carrier = "template " + pr.Template + " (bits " + strings.Join(pr.Bits, " ") + ")"
	case len(pr.Bits) > 0:
		carrier = "bits " + strings.Join(pr.Bits, " ")
	}
	msg := fmt.Sprintf(" %s shape, %s", pr.Shape, carrier)
	if len(pr.Denies) > 0 {
		msg += "; deny-commands: " + rules(pr.Denies)
	}
	if pr.Shape == projection.ShapeNarrow {
		msg += "; deny-commands: everything"
	}
	if len(pr.Allows) > 0 {
		msg += "; allow-commands: " + rules(pr.Allows)
	}
	if len(pr.Omitted) > 0 {
		msg += "; refused by the bits, sent as nothing: " + rules(pr.Omitted)
	}
	if len(pr.Beyond) > 0 {
		msg += "; beyond the level's bits, not sent: " + rules(pr.Beyond)
	}
	return msg + ShortfallText(shortfall(pr, patterns, secrets))
}

// shortfall is where the device is narrower than port49 under pr, as a
// report prints it: up to three commands port49 permits and the device
// refuses, each argument made from a value redaction hides printed redacted
// (probeShown), and beside them the allows sent under bits that do not reach
// them, which may not run (Result.Unreached), redacted.
func shortfall(pr projection.Result, patterns []platform.Redaction, secrets []string) (narrower, unreached []string) {
	src := pr.ProbeSources()
	for _, v := range pr.Narrower(3) {
		narrower = append(narrower, strings.Join(probeShown(v, src, secrets), " "))
	}
	for _, u := range pr.Unreached {
		unreached = append(unreached, u.Rule)
	}
	if len(narrower) > 0 {
		narrower = redacted(patterns, narrower)
	}
	if len(unreached) > 0 {
		unreached = redacted(patterns, unreached)
	}
	return narrower, unreached
}

// ShortfallText is a shortfall as a report's clauses, each after "; ": a
// projection finding's, and a projection change's in policy diff
// (ProjectionChange.Narrower, Unreached). The examples are the model's probe
// commands, built from the rules' words and placeholders rather than typed
// by anyone (`ping configuration`), so the text says so: a reader at 3am
// should not doubt a real command they do not recognize (task 11 review M1).
func ShortfallText(narrower, unreached []string) string {
	var msg string
	if len(narrower) > 0 {
		msg += "; the device refuses what port49 permits, e.g. these probe commands: " + strings.Join(narrower, "; ")
	}
	if len(unreached) > 0 {
		msg += "; sent under bits that do not reach them, which the device may refuse (whether a Junos allow " +
			"runs without its bit is unmeasured): " + strings.Join(unreached, "; ")
	}
	return msg
}

// UnenforcedRules reports every subject whose roles carry command rules on
// a platform that authorizes no command and projects none into its session
// reply (spec §9, "CI: a granted role carries command rules that the
// platform's supports cannot enforce"), once per subject and platform: the
// device never asks, so the rules decide nothing there. On a pinned set that
// projects the platform the rules are its reply, and nothing is reported.
func (p *Policy) UnenforcedRules(now time.Time) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for _, name := range sortedKeys(p.subs) {
		for _, d := range p.env.Devices {
			dialect := p.dialect(d.Platform)
			if dialect.Authorizes("commands") || dialect.Projected() || seen[name+"\x00"+d.Platform] {
				continue
			}
			for _, at := range p.expiryInstants(now) {
				res, err := p.resolve(p.subs[name], d, at)
				if err != nil || len(res.Blob.Rules) == 0 {
					continue
				}
				seen[name+"\x00"+d.Platform] = true
				out = append(out, Finding{Kind: FindingUnenforcedRules, Message: fmt.Sprintf("subject %q on %s "+
					"(supports: %s): its roles carry %d command rules, and %s neither asks port49 about a command nor "+
					"has them rendered into its session reply, so they decide nothing there (spec §9)", name,
					d.Platform, strings.Join(dialect.Supports, ", "), len(res.Blob.Rules), d.Platform)})
				break
			}
		}
	}
	return out
}
