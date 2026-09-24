package policy

import (
	"fmt"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
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
	for _, f := range p.indistinctCeilings() {
		add(FindingCeilingIndistinct, "%s", f)
	}
	for _, a := range p.acked {
		if a.Role != "" && p.hasDeny(a.Rule) {
			add(FindingAcknowledgeStale, "acknowledge: %s %q: the policy still denies %q, so the entry removed nothing "+
				"and acknowledges nothing; delete it (spec §12)", a.Role, a.Rule, a.Rule)
		}
	}
	out = append(out, p.redundantOverrides()...)
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
	var out []Finding
	for _, name := range sortedKeys(p.roles) {
		for _, rule := range p.roles[name].Deny {
			for _, plat := range sortedKeys(platforms) {
				for _, why := range engine.WidenedToAny(rule, p.dialect(plat).EntityClasses, p.normalizeFor(plat)) {
					out = append(out, Finding{Kind: FindingDenyWidened, Message: fmt.Sprintf(
						"role %q: deny %q on %s: %s", name, rule, plat, why)})
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
	var out []Finding
	for _, name := range sortedKeys(p.roles) {
		for _, rule := range p.roles[name].Permit {
			terms, err := engine.ParseRule(rule)
			if err != nil {
				continue
			}
			for _, plat := range sortedKeys(platforms) {
				for _, t := range terms {
					if head, index, ok := engine.SplitName(t.Text); ok && t.Kind == engine.Word {
						out = append(out, Finding{Kind: FindingPermitJoinedName, Message: fmt.Sprintf(
							"role %q: permit %q on %s: `%s` never matches on %s, which sends it as two arguments "+
								"(tests/lab/results/L21-cisco_iosxe.md); write `%s %s`", name, rule, plat, t.Text, plat,
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
					patterns := append(platform.Redactions(plat), p.dialect(plat).Redact...)
					if words, ok := platform.RedactRule(patterns, strings.Fields(rule)); ok {
						on, shown = append(on, plat), words
					}
				}
				if len(on) > 0 {
					out = append(out, Finding{Kind: FindingRuleSecretLiteral, Message: fmt.Sprintf(
						"role %q: %s %q carries a value redaction hides on %s: the value is in the policy file, "+
							"and every log, record and server_msg that echoes the rule shows it redacted",
						name, verdict, strings.Join(shown, " "), strings.Join(on, ", "))})
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
	patterns := p.Redactions()
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
						"platforms.%s.config_checks[%d].match %q carries a value redaction hides: the value is in the "+
							"policy file, and platform show and export print the check redacted", name, i, shown)})
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
					"platforms.%s.device_config[%d] %q carries a value redaction hides: the value is in the policy "+
						"file, and platform show and devices check-config print the line redacted", name, i, shown)})
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
