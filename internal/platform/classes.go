package platform

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// lockTemplates is whether each template user's reference carries a locked
// password line. Juniper documents a template user as one with no
// authentication, which cannot log in locally; tests/lab/results/L12-juniper_*.md
// ("template logins") measures that, and this is true only if it found a
// template user that did accept a local login and that the locked line
// refuses it (plan 5b Task 14).
var lockTemplates = false

// lockLine is the line that locks a template user's local login.
const lockLine = `authentication encrypted-password "*"`

// ReferenceClasses is the device configuration a projected platform's
// replies rest on, as `set` lines (spec §8, "publish the reference class per
// privilege level through port49 platform export"): the adapter's
// device_config lines, then the bitless `remote` template and, under
// BitDeliveryLocalUserName, each level's template user and class carrying the
// level's bits, one bit per line as `show configuration | display set`
// prints them. Each template class and user is written as a replace, a
// `delete` before its `set` lines, so loading the reference clears what was
// written under one: a class allow-commands, which would run for every
// subject at that template past their own denies (L11), or a template user's
// local password. It does not clear what reaches a template from outside it,
// which it cannot name: a configuration group applied from above, such as
// `groups G system login class <*> allow-commands`, still applies to the
// class the load writes, a deactivated ancestor leaves the loaded lines
// inactive, and a protected one makes the load fail. TemplateDrift, through
// `port49 devices check-config`, is what proves a device carries the
// template and nothing more (task 13 review I3). No template user is one that
// can log in locally (lockTemplates). Every class carries `idle-timeout` from
// maxSessionAge, in whole minutes rounded down and at least one: a
// session-only device never asks port49 again after login, so the class's
// own timer is the one limit that ends a session there (spec §5.6; §13
// decision 21).
func ReferenceClasses(d Dialect, maxSessionAge time.Duration) ([]string, error) {
	ts, err := templates(d, maxSessionAge)
	if err != nil {
		return nil, err
	}
	out := slices.Clone(d.DeviceConfig)
	for _, t := range ts {
		out = append(out, "delete system login class "+t.class)
		out = append(out, t.lines(maxSessionAge)...)
	}
	return out, nil
}

// template is one template user and its class.
type template struct {
	user, class string
	bits        []string
}

// templates is `remote`, whose class p49-remote carries no bit, then under
// BitDeliveryLocalUserName each level's template, in name order. It refuses
// what Validate refuses, for a Dialect built past it: a platform that
// projects nothing, an age that is not positive, a template outside port49's
// p49- namespace — the reference deletes each template it writes, and `root`
// or a local account deleted and re-created as a template is not something to
// print — and a template whose class is another's, in any case: p49-remote,
// which would give the fallback `remote` user a level's bits (L18), or one
// two levels share with different bits, which one class cannot carry (spec
// §8, local_user_names; task 13 review I1).
func templates(d Dialect, maxSessionAge time.Duration) ([]template, error) {
	if !d.Projected() {
		return nil, errors.New("the platform projects nothing, so it has no reference classes; its device_config " +
			"is what `platform show` prints")
	}
	if maxSessionAge <= 0 {
		return nil, errors.New("max_session_age must be positive: it is the classes' idle-timeout")
	}
	out := []template{{user: remoteUser, class: RemoteClass}}
	if d.BitDelivery != BitDeliveryLocalUserName {
		return out, nil
	}
	byClass := map[string]template{strings.ToLower(RemoteClass): out[0]}
	for _, level := range sortedKeys(d.LocalUserNames) {
		name := d.LocalUserNames[level]
		if !p49Template.MatchString(name) || !ReservedUsername(name) {
			return nil, fmt.Errorf("local_user_names.%s is not a p49- template, so no reference is written for it "+
				"(spec §8)", level)
		}
		t := template{user: name, class: name, bits: d.CeilingBits[level]}
		if other, ok := byClass[strings.ToLower(name)]; ok {
			if other.class != name || other.user == remoteUser ||
				!slices.Equal(d.ExpandBits(other.bits), d.ExpandBits(t.bits)) {
				return nil, fmt.Errorf("local_user_names.%s: its class is another template's, so no reference is "+
					"written for it: one class carries one set of bits (spec §8)", level)
			}
			continue
		}
		byClass[strings.ToLower(name)] = t
		out = append(out, t)
	}
	return out, nil
}

// lines is the template's class and user as set lines, with the user's
// delete between them.
func (t template) lines(maxSessionAge time.Duration) []string {
	// Unbounded above: Junos's largest idle-timeout is unmeasured, and a
	// reference it refuses fails the load where the operator sees it (task
	// 13 review M5; open for the lab).
	minutes := max(int64(maxSessionAge/time.Minute), 1)
	var out []string
	for _, b := range t.bits {
		out = append(out, fmt.Sprintf("set system login class %s permissions %s", t.class, b))
	}
	out = append(out, fmt.Sprintf("set system login class %s idle-timeout %d", t.class, minutes),
		"delete system login user "+t.user, fmt.Sprintf("set system login user %s class %s", t.user, t.class))
	if lockTemplates {
		out = append(out, fmt.Sprintf("set system login user %s %s", t.user, lockLine))
	}
	return out
}

// paths is where the template lives in the configuration hierarchy: its
// class and its user.
func (t template) paths() [][]string {
	return [][]string{{"system", "login", "class", t.class}, {"system", "login", "user", t.user}}
}

// uidLine is the uid Junos assigns a login user at commit: the one line under
// a template user the reference does not write and the check allows. Any
// digits pass: Junos's uid range, and whether a template can take another
// account's uid, are Task 2's L12 measurements, and the pattern is bounded
// to what they find (task 13 review M4).
var uidLine = regexp.MustCompile(`^set system login user \S+ uid [0-9]+$`)

// templateDriftSays is what a line under a template the reference does not
// write means.
const templateDriftSays = "a line under a port49 template the reference does not write: it changes what every " +
	"subject at that template runs, or lets the template user log in locally; load port49 platform export " +
	"--classes, which replaces the template"

// TemplateDrift reads a projected platform's device configuration, as `show
// configuration | display set` prints it, against ReferenceClasses: every
// reference set line the configuration lacks, and every line under a
// template class or template user the reference does not write (spec §8; plan
// 5b pre-flight I8). A class line the reference lacks — an allow-commands,
// an extra permission — widens every subject at that template, and a template
// user's authentication line lets it log in locally, so each is drift. So is
// what reaches a template from beside it: a `deactivate` of a reference line
// or of any level above one, and a configuration group whose path, wildcards
// read as matching, lands under one, since display set prints a group's lines
// where they are written and not where they apply. The device_config lines
// are Missing's. It is an error where the configuration is not all in set
// form, since a curly-form part could carry anything under a template unread.
func TemplateDrift(config []byte, d Dialect, maxSessionAge time.Duration) (missing []string, extra []ConfigFinding,
	err error) {
	ts, err := templates(d, maxSessionAge)
	if err != nil {
		return nil, nil, err
	}
	var want []string
	var paths [][]string
	for _, t := range ts {
		want = append(want, slices.DeleteFunc(t.lines(maxSessionAge), func(l string) bool {
			return strings.HasPrefix(l, "delete ")
		})...)
		paths = append(paths, t.paths()...)
	}
	carried := map[string]bool{}
	setForm, curly := false, false
	err = eachLine(config, func(n int, line string) {
		words := strings.Fields(line)
		if len(words) == 0 {
			return
		}
		line = strings.Join(words, " ")
		switch words[0] {
		case "set":
			setForm = true
			carried[line] = true
			if slices.Contains(want, line) || uidLine.MatchString(line) {
				return
			}
			if path, wildcards := located(words[1:]); slices.ContainsFunc(paths, func(p []string) bool {
				return hasPrefix(path, p, wildcards)
			}) {
				extra = append(extra, ConfigFinding{Line: n, Text: line, Says: templateDriftSays})
			}
		case "deactivate", "protect":
			// An inactive or protected statement above a template reaches
			// every line under it, so ancestors count as well as descendants.
			if path, wildcards := located(words[1:]); slices.ContainsFunc(paths, func(p []string) bool {
				return hasPrefix(path, p, wildcards) || hasPrefix(p, path, wildcards)
			}) {
				extra = append(extra, ConfigFinding{Line: n, Text: line, Says: templateDriftSays})
			}
		default:
			// Curly form: a statement, a block's open or close, one line or
			// many, a ## annotation after it included. A prompt such as
			// {master:0} and a ## comment are what a captured terminal
			// carries around the output, and neither is configuration.
			if i := strings.Index(line, "##"); i >= 0 {
				line = strings.TrimSpace(line[:i])
			}
			if line != "" && !prompt.MatchString(line) &&
				(strings.ContainsAny(line, "{}") || strings.HasSuffix(line, ";")) {
				curly = true
			}
		}
	})
	if err != nil {
		return nil, nil, err
	}
	switch {
	case !setForm:
		return nil, nil, errors.New("the configuration has no set line: the template check reads `show configuration " +
			"| display set`")
	case curly:
		return nil, nil, errors.New("the configuration mixes curly-form statements into set form, and the template " +
			"check cannot read what a curly block carries under a template: capture the whole `show configuration " +
			"| display set`")
	}
	for _, l := range want {
		if !carried[l] {
			missing = append(missing, l)
		}
	}
	return missing, extra, nil
}

// prompt is a Junos prompt's routing-engine line, {master:0}.
var prompt = regexp.MustCompile(`^\{[^\s{}]*\}$`)

// located is a statement's path, the words after its verb, unquoted and with
// every `groups NAME`, `logical-systems NAME` and `tenants NAME` it sits
// under taken off, so a template is matched wherever it is written. A
// hand-edited capture may quote a plain word `display set` prints bare, and
// a logical system's or tenant's login is port49's to check as well, whether
// or not a session lands there (task 13 review M1, M3). Under a group,
// wildcards is true: a word holding `<p49-*>` or `<*>` matches any word,
// since Junos applies the group wherever it matches.
func located(words []string) (path []string, wildcards bool) {
	for _, w := range words {
		path = append(path, strings.Trim(w, `"`))
	}
	for len(path) > 2 && slices.Contains([]string{"groups", "logical-systems", "tenants"}, path[0]) {
		wildcards = wildcards || path[0] == "groups"
		path = path[2:]
	}
	return path, wildcards
}

// hasPrefix reports whether prefix is a prefix of path, word for word; with
// wildcards, a word of path holding a wildcard character matches any word.
func hasPrefix(path, prefix []string, wildcards bool) bool {
	if len(path) < len(prefix) {
		return false
	}
	for i, w := range prefix {
		if path[i] != w && !(wildcards && strings.ContainsAny(path[i], "<*?[")) {
			return false
		}
	}
	return true
}
