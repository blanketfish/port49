package platform

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
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

// ClassAges is the session ceiling each template class carries as its
// idle-timeout (spec §5.6, §8; decision 55 ruling 14). ByClass holds the least
// positive ceiling among the sessions landing in a class on the platform's
// devices; a zero is a class whose every session is `never`, which gets no
// idle-timeout line. A class absent from ByClass has no session landing in it
// and takes Default, which must be positive.
type ClassAges struct {
	Default time.Duration
	ByClass map[string]time.Duration
}

// of is the class's ceiling: its entry, else Default.
func (a ClassAges) of(class string) time.Duration {
	if age, ok := a.ByClass[class]; ok {
		return age
	}
	return a.Default
}

// idleMinutes is an idle-timeout in whole minutes rounded down and at least
// one.
func idleMinutes(age time.Duration) int64 { return max(int64(age/time.Minute), 1) }

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
// ages, in whole minutes rounded down and at least one, except a class whose
// ceiling is zero (every session in it `never`): a session-only device never
// asks port49 again after login, so the class's own timer is the one limit
// that ends a session there (spec §5.6; §13 decision 21, decision 55 ruling
// 14).
func ReferenceClasses(d Dialect, ages ClassAges) ([]string, error) {
	ts, err := templates(d, ages)
	if err != nil {
		return nil, err
	}
	out := slices.Clone(d.DeviceConfig)
	for _, t := range ts {
		out = append(out, "delete system login class "+t.class)
		out = append(out, t.lines(ages.of(t.class))...)
	}
	return out, nil
}

// ClassNames is the template classes ReferenceClasses writes, in its order.
func ClassNames(d Dialect, ages ClassAges) ([]string, error) {
	ts, err := templates(d, ages)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, t := range ts {
		out = append(out, t.class)
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
func templates(d Dialect, ages ClassAges) ([]template, error) {
	if !d.Projected() {
		return nil, errors.New("the platform projects nothing, so it has no reference classes; its device_config " +
			"is what `platform show` prints")
	}
	if ages.Default <= 0 {
		return nil, errors.New("max_session_age must be positive: it is the classes' idle-timeout")
	}
	for class, age := range ages.ByClass {
		if age < 0 {
			return nil, fmt.Errorf("the age of class %s is negative", class)
		}
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
// delete between them. An age of zero is a class every session in which is
// `never`: it gets no idle-timeout line.
func (t template) lines(age time.Duration) []string {
	var out []string
	for _, b := range t.bits {
		out = append(out, fmt.Sprintf("set system login class %s permissions %s", t.class, b))
	}
	if age != 0 {
		// Unbounded above: Junos's largest idle-timeout is unmeasured, and a
		// reference it refuses fails the load where the operator sees it
		// (task 13 review M5; open for the lab).
		out = append(out, fmt.Sprintf("set system login class %s idle-timeout %d", t.class, idleMinutes(age)))
	}
	out = append(out, "delete system login user "+t.user, fmt.Sprintf("set system login user %s class %s", t.user, t.class))
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
// write means. The inherited capture cannot say which group brought a line,
// so it points at the curly form, which does (L57; decision 44 ruling 7).
const templateDriftSays = "a line under a port49 template the reference does not write: it changes what every " +
	"subject at that template runs, or lets the template user log in locally. If a configuration group put it " +
	"there, `show configuration system login | display inheritance` names the group behind each inherited line " +
	"(## '...' was inherited from group '...'): remove the statement from that group, or narrow the group's " +
	"wildcard past the p49- templates, since loading the reference does not clear it. Otherwise load port49 " +
	"platform export --classes, which replaces the template"

// TemplateDrift reads a projected platform's device configuration, as
// ConfigCapture prints it, against ReferenceClasses: every reference set line
// the configuration lacks, and every line under a template class or template
// user the reference does not write and that is not harmless (spec §8, §12;
// plan 5b pre-flight I8; decision 44 rulings 7 and 9). A class line the
// reference lacks — an allow-commands, an extra permission — widens every
// subject at that template, and a template user's authentication line lets
// it log in locally, so each is drift; a class's idle-timeout, login-alarms
// and login-tip, a user's full-name and an apply-groups-except are not
// (templateLinePasses). The inherited capture prints a configuration group's
// statements expanded under each template they land on, and nothing of the
// group itself (tests/lab/results/L57-juniper_*.md), so a line a group brings
// is judged as the template's own, and its finding points at the curly form
// that names the group. A capture with a `set groups` line, or `apply-groups`
// as a word at any level, was taken without `display inheritance`, its
// groups unexpanded, and is an error naming the first such line (groupSign).
// So is what reaches a template from beside it: a `deactivate` of a reference
// line or of any level above one is drift. The device_config lines are
// Missing's. It is an error where the configuration is not all in set form,
// since a curly-form part could carry anything under a template unread, and
// where it lacks the top-level `set version` line a whole display set
// prints, since a capture of a subtree, `show configuration system login`,
// leaves a deactivate outside it unread (task 13a review I4).
func TemplateDrift(config []byte, d Dialect, ages ClassAges) (missing []string, extra []ConfigFinding,
	err error) {
	ts, err := templates(d, ages)
	if err != nil {
		return nil, nil, err
	}
	var want []string
	var paths [][]string
	// idle is each class's rendered idle-timeout line and minutes. A device
	// value at or below the minutes carries the line (decision 55 ruling 14):
	// a shorter timer ends a session sooner than port49 proved, so only a
	// longer or missing one is drift. A class with no entry here is a `never`
	// class, which any value passes.
	type idleLine struct {
		line    string
		minutes int64
	}
	idle := map[string]idleLine{}
	for _, t := range ts {
		want = append(want, slices.DeleteFunc(t.lines(ages.of(t.class)), func(l string) bool {
			return strings.HasPrefix(l, "delete ")
		})...)
		paths = append(paths, t.paths()...)
		if age := ages.of(t.class); age != 0 {
			idle[t.class] = idleLine{fmt.Sprintf("set system login class %s idle-timeout %d", t.class, idleMinutes(age)),
				idleMinutes(age)}
		}
	}
	carried := map[string]bool{}
	setForm, curly, version := false, false, false
	var notInherited error
	var strayCR error
	err = eachLine(config, func(n int, line string) {
		// eachLine took one trailing carriage return as a line ending; any
		// other could join two statements into one line.
		if strayCR == nil && strings.Contains(line, "\r") {
			strayCR = fmt.Errorf("line %d holds a carriage return that does not end it: capture the configuration "+
				"with `%s`", n, ConfigCapture)
		}
		words := strings.Fields(line)
		if len(words) == 0 {
			return
		}
		line = strings.Join(words, " ")
		if notInherited == nil && slices.Contains([]string{"set", "deactivate", "protect"}, words[0]) &&
			groupSign(line) {
			notInherited = fmt.Errorf("line %d %s: capture the whole configuration with `%s`", n, notInheritedWhy,
				ConfigCapture)
		}
		switch words[0] {
		case "set":
			setForm = true
			carried[line] = true
			if len(words) == 3 && strings.EqualFold(strings.Trim(words[1], `"`), "version") {
				version = true
			}
			if len(words) == 7 {
				path, _ := located(words[1:])
				if len(path) == 6 && path[0] == "system" && path[1] == "login" && path[2] == "class" &&
					path[4] == "idle-timeout" {
					if il, ok := idle[path[3]]; ok {
						if n, perr := strconv.ParseInt(path[5], 10, 64); perr == nil && n >= 1 && n <= il.minutes {
							carried[il.line] = true
						}
					}
				}
			}
			if slices.Contains(want, line) || uidLine.MatchString(line) {
				return
			}
			arity := statementArity(line)
			if path, wildcards := located(words[1:]); slices.ContainsFunc(paths, func(p []string) bool {
				return hasPrefix(path, p, wildcards) && !templateLinePasses(path, p, arity)
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
	if strayCR != nil {
		return nil, nil, strayCR
	}
	if notInherited != nil {
		return nil, nil, notInherited
	}
	switch {
	case !setForm:
		return nil, nil, errors.New("the configuration has no set line: the template check reads `" + ConfigCapture + "`")
	case !version:
		return nil, nil, errors.New("the configuration has no top-level set version line, which a whole `show " +
			"configuration | display set` prints: a capture of part of it leaves what reaches a template from " +
			"outside that part unread: capture the whole configuration with `" + ConfigCapture + "`")
	case curly:
		return nil, nil, errors.New("the configuration mixes curly-form statements into set form, and the template " +
			"check cannot read what a curly block carries under a template: capture the whole configuration with `" +
			ConfigCapture + "`")
	}
	for _, l := range want {
		if !carried[l] {
			missing = append(missing, l)
		}
	}
	return missing, extra, nil
}

// prompt is a Junos prompt's routing-engine line, {master:0}, with the
// configuration-mode tail a capture taken there carries, {master:0}[edit]
// (task 13 re-review M6).
var prompt = regexp.MustCompile(`^\{[^\s{}]*\}(\[edit[^\]]*\])?$`)

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

// harmlessTemplateStatements change nothing a session runs: a class's
// idle-timeout (the reference writes one; a value above it is the reference's
// line missing), login banner and alarms, and a user's full name. Under a
// template they pass, written there or expanded from a group (spec §12;
// decision 44 ruling 7). Every other statement the reference does not write
// fails, a privilege one or one on neither list (ruling 9).
//
// Each maps to the words it takes after the template: a flag is one word, a
// valued statement two, so nothing rides behind a harmless word on the same
// line (a space-joined capture could hide a privilege statement there).
var harmlessTemplateStatements = map[string]map[string]int{
	"class": {"idle-timeout": 2, "login-alarms": 1, "login-tip": 1},
	"user":  {"full-name": 2},
}

// templateLinePasses reports whether a line at path, under template path t,
// passes though the reference does not write it: a harmless statement of t's
// kind, or an apply-groups-except, which keeps a group off the template and
// is no finding where it survives inheritance (L57; both inherited forms strip
// it beside a class-level apply-groups; decision 44 ruling 7).
// arity is the line's path length counting a quoted string as one word, or -1
// where the line cannot be split into words, which passes nothing.
func templateLinePasses(path, t []string, arity int) bool {
	if len(path) <= len(t) || arity < 0 {
		return false
	}
	stmt := path[len(t)]
	if stmt == "apply-groups-except" {
		return arity == len(t)+2
	}
	words, ok := harmlessTemplateStatements[t[2]][stmt]
	return ok && arity == len(t)+words
}

// statementArity is the length of a statement's path as located reads it,
// counting a quoted string as one word, or -1 where the line cannot be split.
func statementArity(line string) int {
	sw, ok := statementWords(line)
	if !ok || len(sw) < 2 {
		return -1
	}
	var texts []string
	for _, w := range sw[1:] {
		texts = append(texts, w.text)
	}
	path, _ := located(texts)
	return len(path)
}
