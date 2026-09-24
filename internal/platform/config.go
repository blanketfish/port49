package platform

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

// LocalAccount is a device-local account a configuration declares, and the
// line that declares it.
type LocalAccount struct {
	Name string
	Line int
}

// ConfigFinding is a configuration line one of the adapter's checks names:
// Check is the check's index in the adapter's ConfigChecks.
type ConfigFinding struct {
	Line  int
	Text  string
	Says  string
	Check int
}

// ReadConfig reads a device's configuration text, as `show running-config`
// prints it, against the adapter: every local account its LocalAccounts
// patterns name, every line a ConfigChecks entry matches, and an error where
// the text could not be read to the end. It is a lab and CI instrument: port49
// never logs into a device (spec §8, "Verification").
func (d Dialect) ReadConfig(config []byte) ([]LocalAccount, []ConfigFinding, error) {
	var accounts []LocalAccount
	var findings []ConfigFinding
	var accountRes, checkRes []*regexp.Regexp
	// Validate compiled every pattern; one that does not compile here is
	// skipped rather than trusted to panic.
	for _, p := range d.LocalAccounts {
		if re, err := regexp.Compile(p); err == nil && re.NumSubexp() == 1 {
			accountRes = append(accountRes, re)
		}
	}
	checks := make(map[*regexp.Regexp]int)
	for i, c := range d.ConfigChecks {
		if re, err := regexp.Compile(c.Match); err == nil {
			checkRes, checks[re] = append(checkRes, re), i
		}
	}
	err := eachLine(config, func(n int, line string) {
		for _, re := range accountRes {
			if m := re.FindStringSubmatch(line); m != nil {
				accounts = append(accounts, LocalAccount{Name: m[1], Line: n})
			}
		}
		for _, re := range checkRes {
			if re.MatchString(line) {
				i := checks[re]
				findings = append(findings, ConfigFinding{Line: n, Text: line, Says: d.ConfigChecks[i].Says, Check: i})
			}
		}
	})
	if err != nil {
		return nil, nil, err
	}
	return accounts, findings, nil
}

// Missing is every line of required, an adapter's DeviceConfig, that the
// configuration does not carry as a top-level line of its own, with runs of
// whitespace read as one space: a line the adapter's renderings depend on is
// checked by its presence, which no ConfigChecks entry can do (IOS-XE's
// level-7 command method list, spec §6). A line indented under another
// command, or carrying more words, is not the line. It is an error where the
// text could not be read to the end.
func Missing(config []byte, required []string) ([]string, error) {
	carried := map[string]bool{}
	err := eachLine(config, func(_ int, line string) {
		if line != "" && !unicode.IsSpace(rune(line[0])) {
			carried[strings.Join(strings.Fields(line), " ")] = true
		}
	})
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, line := range required {
		if !carried[strings.Join(strings.Fields(line), " ")] {
			missing = append(missing, line)
		}
	}
	return missing, nil
}

// eachLine calls fn with each line of config and its number, from 1. A read
// that stopped short is not a clean configuration: whatever followed the line
// it stopped at was never checked, so it is an error, and it quotes nothing
// from the text.
func eachLine(config []byte, fn func(n int, line string)) error {
	sc := bufio.NewScanner(bytes.NewReader(config))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for n := 1; sc.Scan(); n++ {
		fn(n, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("the configuration was not read to the end: %w", err)
	}
	return nil
}

// ConfigFloor is d, the adapter a policy gives a platform, with the set's
// adapter ref laid under what the configuration check reads: ref's
// device_config lines, local_accounts patterns and config_checks come first,
// and d's own follow where ref lacks them. A `platforms:` block adds to what
// the check holds a device to and never takes from it, `replace: true`
// included, since the device behind the name is the same device: a block
// that rewrites a set line ending in `local` to end in `none` still has the
// set's line required, and its own flagged by the set's checks.
func ConfigFloor(d, ref Dialect) Dialect {
	d = d.clone()
	d.DeviceConfig = union(ref.DeviceConfig, d.DeviceConfig)
	d.LocalAccounts = union(ref.LocalAccounts, d.LocalAccounts)
	d.ConfigChecks = union(ref.ConfigChecks, d.ConfigChecks)
	return d
}

// union is base, then every element of more base lacks, in a new slice; nil
// where both are empty.
func union[T comparable](base, more []T) []T {
	var out []T
	for _, list := range [][]T{base, more} {
		for _, e := range list {
			if !slices.Contains(out, e) {
				out = append(out, e)
			}
		}
	}
	return out
}

// RedactConfigLine is a configuration line as port49 may print it: its runs of
// whitespace one space, and every word rules hide «redacted», since a device
// configuration and a block's device_config are full of secrets (spec §5.8).
// A line some built-in set's adapter ships as device_config is printed as
// written: it is lab text, never a secret, and the abbreviation matching that
// reads `authentication` as `authentication-key` would otherwise hide which
// line a device lacks.
func RedactConfigLine(rules []Redaction, line string) string {
	line = strings.Join(strings.Fields(line), " ")
	for _, set := range sets {
		for _, d := range set {
			if slices.Contains(d.DeviceConfig, line) {
				return line
			}
		}
	}
	return RedactProse(rules, line)
}

// ShippedConfigCheck reports whether some built-in set's adapter ships c, as
// written: its match reads a method list or an authentication order, lines
// that carry no secret, and its says is lab text. Any other check is a
// `platforms:` block's, which may match any line and say anything.
func ShippedConfigCheck(c ConfigCheck) bool {
	for _, set := range sets {
		for _, d := range set {
			if slices.Contains(d.ConfigChecks, c) {
				return true
			}
		}
	}
	return false
}

// ShippedConfigMatch reports whether some built-in set's adapter ships a
// config check whose match is match: lab text, never a secret, whatever a
// block's check says beside it.
func ShippedConfigMatch(match string) bool {
	for _, set := range sets {
		for _, d := range set {
			for _, c := range d.ConfigChecks {
				if c.Match == match {
					return true
				}
			}
		}
	}
	return false
}

// RedactConfigCheck is c as port49 may print it: as written where a set ships
// it (ShippedConfigCheck), and otherwise its says redacted as prose by rules,
// and its match too unless a set ships that match (ShippedConfigMatch), since
// a block's text may carry a secret (spec §5.8).
func RedactConfigCheck(rules []Redaction, c ConfigCheck) ConfigCheck {
	if ShippedConfigCheck(c) {
		return c
	}
	out := ConfigCheck{Match: c.Match, Says: RedactProse(rules, c.Says)}
	if !ShippedConfigMatch(c.Match) {
		out.Match = RedactProse(rules, c.Match)
	}
	return out
}

// shippedBy reports whether some built-in set's adapter satisfies has: text a
// set ships is lab text, never a secret, and prints as written.
func shippedBy(has func(Dialect) bool) bool {
	for _, set := range sets {
		for _, d := range set {
			if has(d) {
				return true
			}
		}
	}
	return false
}

// ShippedText reports whether some built-in set's adapter ships text as one
// of the values a block can also write: a device_config line, a config
// check's match or says, an unreachable rule, a fallback text or an entity
// class pattern. Such text is lab text, never a secret, and prints as written
// wherever port49 quotes it.
func ShippedText(text string) bool {
	return shippedBy(func(d Dialect) bool {
		if slices.Contains(d.DeviceConfig, text) || slices.ContainsFunc(d.ConfigChecks, func(c ConfigCheck) bool {
			return c.Match == text || c.Says == text
		}) {
			return true
		}
		for _, list := range d.Unreachable {
			if slices.Contains(list, text) {
				return true
			}
		}
		for _, t := range d.Fallback {
			if t == text {
				return true
			}
		}
		for _, list := range d.EntityClasses {
			if slices.Contains(list, text) {
				return true
			}
		}
		return false
	})
}

// RedactUnreachable is an unreachable rule as port49 may print it: as
// written where a set ships it, and otherwise redacted as a rule is
// (RedactRule), since a block's rule is policy text like a role's (spec §5.8).
func RedactUnreachable(rules []Redaction, rule string) string {
	if shippedBy(func(d Dialect) bool {
		for _, list := range d.Unreachable {
			if slices.Contains(list, rule) {
				return true
			}
		}
		return false
	}) {
		return rule
	}
	words, _ := RedactRule(rules, strings.Fields(rule))
	return strings.Join(words, " ")
}

// RedactFallback is a fallback text as port49 may print it: as written where
// a set ships it as measured, and otherwise redacted as prose (RedactProse):
// a block's text, or its note, is the operator's and may say anything.
func RedactFallback(rules []Redaction, text string) string {
	if shippedBy(func(d Dialect) bool {
		for _, t := range d.Fallback {
			if t == text {
				return true
			}
		}
		return false
	}) {
		return text
	}
	return RedactProse(rules, text)
}

// RedactClassPatterns is an entity class's patterns as port49 may print
// them. A class a rule names where a value is redacted holds those values,
// `snmp-server community @bad **` bad communities, and every pattern reads
// Redacted, as the blob event writes it; otherwise a pattern a set ships for
// the class prints as written, and any other is redacted as prose, since a
// block's regex may spell a secret out.
func RedactClassPatterns(rules []Redaction, class string, patterns []string, secret bool) []string {
	out := make([]string, len(patterns))
	for i, p := range patterns {
		switch {
		case secret:
			out[i] = Redacted
		case shippedBy(func(d Dialect) bool { return slices.Contains(d.EntityClasses[class], p) }):
			out[i] = p
		default:
			out[i] = RedactProse(rules, p)
		}
	}
	return out
}

// RedactAdapter is d with every text a `platforms:` block can write that may
// carry a secret as port49 may print it (spec §5.8): its device_config lines
// and config checks (RedactConfigLine, RedactConfigCheck), its
// unreachable rules, its fallback text and note, and its entity classes'
// patterns, secret naming the classes a rule names where a value is
// redacted. A set's own text prints as written.
func RedactAdapter(patterns []Redaction, secret map[string]bool, d Dialect) Dialect {
	if d.DeviceConfig != nil {
		lines := make([]string, len(d.DeviceConfig))
		for i, line := range d.DeviceConfig {
			lines[i] = RedactConfigLine(patterns, line)
		}
		d.DeviceConfig = lines
	}
	if d.ConfigChecks != nil {
		checks := make([]ConfigCheck, len(d.ConfigChecks))
		for i, c := range d.ConfigChecks {
			checks[i] = RedactConfigCheck(patterns, c)
		}
		d.ConfigChecks = checks
	}
	if d.Unreachable != nil {
		unreachable := make(map[string][]string, len(d.Unreachable))
		for level, rules := range d.Unreachable {
			unreachable[level] = make([]string, len(rules))
			for i, rule := range rules {
				unreachable[level][i] = RedactUnreachable(patterns, rule)
			}
		}
		d.Unreachable = unreachable
	}
	for _, texts := range []*map[string]string{&d.Fallback, &d.FallbackNote} {
		if *texts == nil {
			continue
		}
		out := make(map[string]string, len(*texts))
		for level, text := range *texts {
			out[level] = RedactFallback(patterns, text)
		}
		*texts = out
	}
	if d.EntityClasses != nil {
		classes := make(map[string][]string, len(d.EntityClasses))
		for class, list := range d.EntityClasses {
			classes[class] = RedactClassPatterns(patterns, class, list, secret[class])
		}
		d.EntityClasses = classes
	}
	return d
}
