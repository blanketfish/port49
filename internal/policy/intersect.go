package policy

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/engine"
	"github.com/rhwendt/port49/internal/platform"
)

// The intersection checks of spec §12: the effective permission set is what
// the device offers intersected with what port49 permits (§6), and CI names
// where the two disagree. A dead rule is a permit the device never lets a
// session reach; a fallback exposure is a session the device gives more than
// port49 does once port49 cannot answer. Both read each subject's
// composition on each device at now and at every later grant expiry, as the
// shadowed-deny report does, and each is said once per role or subject,
// platform and level.
const (
	FindingDeadRule         = "dead_rule"
	FindingFallbackExposure = "fallback_exposure"
)

func (p *Policy) intersections(now time.Time) []Finding {
	var out []Finding
	seen := map[string]bool{}
	add := func(kind, key, format string, args ...any) {
		if !seen[kind+"\x00"+key] {
			seen[kind+"\x00"+key] = true
			out = append(out, Finding{Kind: kind, Message: fmt.Sprintf(format, args...)})
		}
	}
	instants, redact := p.expiryInstants(now), p.Redactions()
	for _, name := range sortedKeys(p.subs) {
		for _, d := range p.env.Devices {
			for _, at := range instants {
				res, err := p.resolve(p.subs[name], d, at)
				if err != nil || res.Level == "" {
					continue
				}
				dialect := p.dialect(d.Platform)
				attrs, level, ok := p.render(dialect, res.Level)
				if !ok {
					continue
				}
				on := fmt.Sprintf("%s (%s) on %s", level, strings.Join(attrs, ", "), d.Platform)
				// What the set measured cites its lab note; what a block added is
				// the operator's word and says so (task 14 review M7).
				unreachable, operator := dialect.Unreachable[level], dialect.UnreachableNote[level]
				for _, role := range res.Roles {
					for _, rule := range p.roles[role].Permit {
						key := role + "\x00" + rule + "\x00" + d.Platform + "\x00" + level
						switch {
						case len(unreachable) > 0 && p.dead(rule, unreachable, d.Platform, dialect):
							add(FindingDeadRule, key,
								"role %q: permit %q cannot be reached at %s: the device refuses every command it "+
									"matches in its own parser and never asks port49 (unreachable: %s; "+
									"tests/lab/results/ceiling-%s.md)", role, rule, on,
								strings.Join(redacted(redact, unreachable), ", "),
								d.Platform)
						case len(operator) > 0 && p.dead(rule, slices.Concat(unreachable, operator), d.Platform, dialect):
							add(FindingDeadRule, key,
								"role %q: permit %q cannot be reached at %s: the policy's platforms: block says the "+
									"device refuses every command it matches in its own parser (operator-listed "+
									"unreachable, not measured: %s)", role, rule, on,
								strings.Join(redacted(redact, operator), ", "))
						}
					}
				}
				// The device's fallback reads the reply it was sent, not the
				// level's name: a role or grant that sends a higher level's
				// role is exposed as that level is (final review I1).
				exposed := p.deliveredLevel(dialect, res.Level, res.Blob.Attributes)
				if _, rendered, ok := p.render(dialect, exposed); ok {
					exposed = rendered
				}
				if exposed != level {
					on = fmt.Sprintf("%s on %s, whose reply (%s) reaches %s", level, d.Platform,
						strings.Join(res.Blob.Attributes, ", "), exposed)
				}
				fallback, note := dialect.Fallback[exposed], dialect.FallbackNote[exposed]
				if (fallback != "" || note != "") && confined(res.Blob) {
					add(FindingFallbackExposure, name+"\x00"+d.Platform+"\x00"+exposed,
						"subject %q at %s: port49's rules confine it to %s, and if port49 cannot answer and the device "+
							"falls back to local it gets %s: more than the policy grants (spec §6, §12)", name, on,
						strings.Join(redacted(redact, permitsOf(res.Blob)), ", "), fallbackText(redact, fallback, note))
				}
			}
		}
	}
	return out
}

// dead reports whether every command permit matches is one of unreachable's:
// the probes both rule sets tell apart, each decided as the device would send
// it on the platform. A permit that matches nothing probed is not called dead.
func (p *Policy) dead(permit string, unreachable []string, platformName string, dialect platform.Dialect) bool {
	blob := func(rules []string) *engine.Program {
		b := engine.Blob{Version: engine.Version, Bundle: "intersection", Platform: platformName,
			Normalize: p.normalizeFor(platformName), Classes: dialect.EntityClasses}
		for _, r := range rules {
			b.Rules = append(b.Rules, engine.Rule{Verdict: engine.Permit, Rule: r, Role: "r"})
		}
		prog, err := engine.Compile(b)
		if err != nil {
			return nil
		}
		return prog
	}
	mine, theirs := blob([]string{permit}), blob(unreachable)
	if mine == nil || theirs == nil {
		return false
	}
	matched := false
	for _, v := range engine.Probes(mine, theirs) {
		raw := probeRaw(v)
		if !mine.Command(raw).Permit {
			continue
		}
		if !theirs.Command(raw).Permit {
			return false
		}
		matched = true
	}
	return matched
}

// confined reports whether a composition's rules deny any command: a session
// they permit everything to has nothing a fallback could add. Without a `**`
// permit some command matches no permit; with one, a deny binds on a command
// the probes find.
func confined(b engine.Blob) bool {
	if !slices.ContainsFunc(b.Rules, func(r engine.Rule) bool { return r.Verdict == engine.Permit && r.Rule == "**" }) {
		return true
	}
	prog, err := engine.Compile(b)
	if err != nil {
		return true
	}
	for _, v := range engine.Probes(prog) {
		if !prog.Command(probeRaw(v)).Permit {
			return true
		}
	}
	return false
}

// permitsOf is a composition's permits as review reads them.
func permitsOf(b engine.Blob) []string {
	var out []string
	for _, r := range b.Rules {
		if r.Verdict == engine.Permit && !slices.Contains(out, r.Rule) {
			out = append(out, r.Rule)
		}
	}
	if len(out) == 0 {
		return []string{"nothing"}
	}
	return out
}

// fallbackText is what the exposure says the device gives: the set's
// measured text, or that no set measured one, then a block's own text as the
// operator's note. The note is quoted in ASCII, so nothing in it can close
// it or read as the measurement, a printable look-alike of a parenthesis or
// a quote included (spec §12); only the redaction marker is left as it reads. Both are prose a `platforms:` block
// can write, redacted here (platform.RedactProse).
func fallbackText(patterns []platform.Redaction, set, note string) string {
	text := "what no platform set measured"
	if set != "" {
		text = platform.RedactProse(patterns, set)
	}
	if note != "" {
		marker := strings.Trim(strconv.QuoteToASCII(platform.Redacted), `"`)
		text += " (operator note: " + strings.ReplaceAll(strconv.QuoteToASCII(platform.RedactProse(patterns, note)), marker,
			platform.Redacted) + ")"
	}
	return text
}

// redacted is rules as a report lists them unquoted, each redacted by
// patterns: the printer redacts only quoted values, so a list it cannot see
// into is redacted here (spec §5.8). A `platforms:` block's unreachable
// rules are policy text like a role's.
func redacted(patterns []platform.Redaction, rules []string) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		words, _ := platform.RedactRule(patterns, strings.Fields(r))
		out[i] = strings.Join(words, " ")
	}
	return out
}

// probeRaw is a probe vector as a device sends it.
func probeRaw(v []string) []string {
	raw := []string{"service=shell", "cmd=" + v[0]}
	for _, a := range v[1:] {
		raw = append(raw, "cmd-arg="+a)
	}
	return raw
}
