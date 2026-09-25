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
// `delete` before its `set` lines, so loading the reference over a device
// leaves nothing of what was there: a class allow-commands, which would run
// for every subject at that template past their own denies (L11), or a
// template user's local password. No template user is one that can log in
// locally (lockTemplates). Every class carries `idle-timeout` from
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
// a platform that projects nothing, an age that is not positive, and a
// template outside port49's p49- namespace, which Validate refuses too: the
// reference deletes each template it writes, and `root` or a local account
// deleted and re-created as a template is not something to print (spec §8,
// local_user_names).
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
	seen := map[string]bool{}
	for _, level := range sortedKeys(d.LocalUserNames) {
		name := d.LocalUserNames[level]
		if !p49Template.MatchString(name) || !ReservedUsername(name) {
			return nil, fmt.Errorf("local_user_names.%s is not a p49- template, so no reference is written for it "+
				"(spec §8)", level)
		}
		if !seen[name] {
			seen[name] = true
			out = append(out, template{user: name, class: name, bits: d.CeilingBits[level]})
		}
	}
	return out, nil
}

// lines is the template's class and user as set lines, with the user's
// delete between them.
func (t template) lines(maxSessionAge time.Duration) []string {
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
// a template user the reference does not write and the check allows.
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
			if under(words[1:], paths) {
				extra = append(extra, ConfigFinding{Line: n, Text: line, Says: templateDriftSays})
			}
		case "deactivate", "protect":
			// An inactive or protected statement above a template reaches
			// every line under it, so ancestors count as well as descendants.
			if slices.ContainsFunc(paths, func(p []string) bool {
				return hasPrefix(words[1:], p, false) || hasPrefix(p, words[1:], false)
			}) {
				extra = append(extra, ConfigFinding{Line: n, Text: line, Says: templateDriftSays})
			}
		default:
			// Curly form: a statement, a block's open or close. A prompt such
			// as {master:0} and a ## comment are what a captured terminal
			// carries around the output, and neither is configuration.
			last := line[len(line)-1]
			if last == ';' || last == '{' || line == "}" {
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

// under reports whether a set line's path, the words after `set`, is at or
// below one of paths. Under `groups NAME` the rest is matched with a
// wildcard word, `<p49-*>` or `<*>`, read as matching any word, since Junos
// applies it wherever it matches.
func under(path []string, paths [][]string) bool {
	group := len(path) > 2 && path[0] == "groups"
	if group {
		path = path[2:]
	}
	return slices.ContainsFunc(paths, func(p []string) bool { return hasPrefix(path, p, group) })
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
