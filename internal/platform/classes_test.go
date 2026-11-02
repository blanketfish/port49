package platform

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// The reference replaces each template class and user, a delete before its
// set lines, so nothing a device carried under one survives the load (I8).
// The classes carry the level's bits, one per line, and an idle-timeout from
// max_session_age (decision 21); the remote template has no bits, and no
// template user can log in locally (I9).
func TestReferenceClasses(t *testing.T) {
	d := junosProjected(BitDeliveryLocalUserName)
	d.DeviceConfig = []string{"set system tacplus-options strict-authorization"}
	got, err := ReferenceClasses(d, ClassAges{Default: 12*time.Hour + 59*time.Second})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"set system tacplus-options strict-authorization",
		"delete system login class p49-remote",
		"set system login class p49-remote idle-timeout 720",
		"delete system login user remote",
		"set system login user remote class p49-remote",
		"delete system login class p49-admin",
		"set system login class p49-admin permissions all",
		"set system login class p49-admin idle-timeout 720",
		"delete system login user p49-admin",
		"set system login user p49-admin class p49-admin",
		"delete system login class p49-readonly",
		"set system login class p49-readonly permissions view",
		"set system login class p49-readonly permissions view-configuration",
		"set system login class p49-readonly idle-timeout 720",
		"delete system login user p49-readonly",
		"set system login user p49-readonly class p49-readonly",
	}
	if lockTemplates {
		// Each user's set lines end with the lock (plan 5b Task 14).
		var locked []string
		for _, l := range want {
			locked = append(locked, l)
			if strings.HasPrefix(l, "set system login user ") {
				locked = append(locked, strings.Replace(l, "class "+l[strings.LastIndex(l, " ")+1:], lockLine, 1))
			}
		}
		want = locked
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%q", got)
	}
	for _, l := range got {
		if strings.Contains(l, "authentication") && !strings.HasSuffix(l, lockLine) {
			t.Errorf("a template user that can log in locally: %s", l)
		}
	}
	up, _ := ReferenceClasses(junosProjected(BitDeliveryUserPermissions), ClassAges{Default: 30 * time.Second})
	if up[1] != "set system login class p49-remote idle-timeout 1" {
		t.Fatalf("user_permissions: %q", up)
	}
	// What export prints for the shipped Junos adapter carries every line
	// check-config holds a Junos device to.
	junos, _ := DialectFor("juniper_junos")
	ref, err := ReferenceClasses(junos, ClassAges{Default: 12 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if missing, err := Missing([]byte(strings.Join(ref, "\n")), junos.DeviceConfig); err != nil || len(missing) != 0 {
		t.Fatalf("%q %v", missing, err)
	}
	eos, _ := DialectFor("arista_eos")
	if _, err := ReferenceClasses(eos, ClassAges{Default: time.Hour}); err == nil {
		t.Error("a platform that projects nothing has no classes")
	}
}

// A template outside the p49- namespace is never written, even on a Dialect
// built past Validate: `root` would be deleted and re-created as a bitless
// template (spec §8, local_user_names).
func TestReferenceClassesRefusesATemplateOutsideP49(t *testing.T) {
	for _, name := range []string{"root", "remote", "noc", "P49-ADMIN"} {
		d := junosProjected(BitDeliveryLocalUserName)
		d.LocalUserNames["admin"] = name
		if _, err := ReferenceClasses(d, ClassAges{Default: time.Hour}); err == nil {
			t.Errorf("%s: written", name)
		}
		if _, _, err := TemplateDrift([]byte("set system host-name srx1\n"), d, ClassAges{Default: time.Hour}); err == nil {
			t.Errorf("%s: checked", name)
		}
	}
}

// The template check reads a display-set configuration against the
// reference: a line it lacks, and any line under a template class or user it
// does not write — a class allow-commands (M8), a template password — are
// drift; the uid Junos assigns is not (I8, I9).
func TestTemplateDrift(t *testing.T) {
	d := junosProjected(BitDeliveryLocalUserName)
	ref, _ := ReferenceClasses(d, ClassAges{Default: time.Hour})
	var config []string
	for _, l := range ref {
		if !strings.HasPrefix(l, "delete ") {
			config = append(config, l)
		}
	}
	config = append(config, "set system login user p49-admin uid 2001", "set system host-name srx1",
		"set version 21.4R3")
	missing, extra, err := TemplateDrift([]byte(strings.Join(config, "\n")), d, ClassAges{Default: time.Hour})
	if err != nil || len(missing) != 0 || len(extra) != 0 {
		t.Fatalf("clean: %q %+v %v", missing, extra, err)
	}
	drifted := append(config[1:], `set system login class p49-remote allow-commands "^configure"`,
		`set system login user p49-readonly authentication encrypted-password "$6$x"`,
		"set system login class p49-readonly permissions   clear")
	missing, extra, err = TemplateDrift([]byte(strings.Join(drifted, "\n")), d, ClassAges{Default: time.Hour})
	if err != nil || !reflect.DeepEqual(missing, []string{config[0]}) || len(extra) != 3 ||
		extra[2].Text != "set system login class p49-readonly permissions clear" {
		t.Fatalf("drift: %q %+v %v", missing, extra, err)
	}
	if _, _, err := TemplateDrift([]byte("system {\n  login {\n  }\n}\n"), d, ClassAges{Default: time.Hour}); err == nil ||
		!strings.Contains(err.Error(), "display set") {
		t.Fatalf("curly form: %v", err)
	}
	// A capture of the subtree the templates live in, `show configuration
	// system login | display set`, lacks the set version line a whole one
	// prints: the rest was never read, so it is not a clean device (task
	// 13a review I4).
	for _, partial := range [][]string{config[:len(config)-1],
		append(config[:len(config)-1:len(config)-1], "set logical-systems ls1 version 21.4R3"),
		append(config[:len(config)-1:len(config)-1], "deactivate version")} {
		if _, _, err := TemplateDrift([]byte(strings.Join(partial, "\n")), d, ClassAges{Default: time.Hour}); err == nil ||
			!strings.Contains(err.Error(), "set version") {
			t.Errorf("partial %q: %v", partial[len(partial)-1], err)
		}
	}
}

// cleanCapture is the reference as `display set` prints it once loaded.
func cleanCapture(t *testing.T, d Dialect) []string {
	t.Helper()
	ref, err := ReferenceClasses(d, ClassAges{Default: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	out := []string{"set version 21.4R3", "set system host-name srx1"}
	for _, l := range ref {
		if !strings.HasPrefix(l, "delete ") {
			out = append(out, l)
		}
	}
	return out
}

// A class that carries more than the reference is the escalation the check
// exists for: every subject sent to that template runs what the extra bit
// reaches, whatever port49 proved. Each way a device can carry more under a
// template is drift: an extra bit, a different idle-timeout, a template user
// moved to another class, a deactivated reference line or an ancestor of one,
// a group line, which only a capture taken without display inheritance carries, and a curly-form section a capture
// mixes in, which the set-form reader cannot see into.
func TestTemplateDriftFailsEveryWayToCarryMore(t *testing.T) {
	d := junosProjected(BitDeliveryLocalUserName)
	for _, c := range []struct {
		name, line string
		missing    bool
	}{
		{"an extra bit", "set system login class p49-readonly permissions all", false},
		{"an extra bit on remote", "set system login class p49-remote permissions view", false},
		{"a class deny beside", `set system login class p49-admin deny-commands "^request"`, false},
		{"a template in another class", "set system login user p49-readonly class super-user", false},
		{"a deactivated idle-timeout", "deactivate system login class p49-admin idle-timeout", false},
		{"a deactivated class", "deactivate system login class p49-readonly", false},
		{"a deactivated login", "deactivate system login", false},
	} {
		config := append(cleanCapture(t, d), c.line)
		missing, extra, err := TemplateDrift([]byte(strings.Join(config, "\n")), d, ClassAges{Default: time.Hour})
		if err != nil || len(extra) != 1 || extra[0].Line != len(config) || len(missing) != 0 {
			t.Errorf("%s: %q %+v %v", c.name, missing, extra, err)
		}
	}
	// A group line is a capture taken without `display inheritance`, its
	// groups unexpanded: refused at that line (decision 44 ruling 7; L57).
	for _, line := range []string{"set system login class p49-readonly apply-groups wide",
		`set groups wide system login class p49-readonly allow-commands ".*"`,
		"set groups wide system login class <p49-*> permissions all",
		"set groups wide system login <*> p49-readonly permissions all",
		"set groups wide system login user noc full-name x"} {
		config := append(cleanCapture(t, d), line)
		if _, _, err := TemplateDrift([]byte(strings.Join(config, "\n")), d, ClassAges{Default: time.Hour}); err == nil ||
			!strings.HasPrefix(err.Error(), fmt.Sprintf("line %d ", len(config))) ||
			!strings.Contains(err.Error(), ConfigCapture) {
			t.Errorf("%s: %v", line, err)
		}
	}
	// A timeout the reference does not write is the reference's line missing;
	// the device's own value is harmless, so no extra.
	config := cleanCapture(t, d)
	for i, l := range config {
		if l == "set system login class p49-admin idle-timeout 60" {
			config[i] = "set system login class p49-admin idle-timeout 100000"
		}
	}
	missing, extra, err := TemplateDrift([]byte(strings.Join(config, "\n")), d, ClassAges{Default: time.Hour})
	if err != nil || !reflect.DeepEqual(missing, []string{"set system login class p49-admin idle-timeout 60"}) ||
		len(extra) != 0 {
		t.Errorf("idle-timeout: %q %+v %v", missing, extra, err)
	}
	// Lines under other classes, users and groups are not the check's.
	other := append(cleanCapture(t, d), "set system login class noc permissions all",
		"set system login user noc class super-user",
		"deactivate system login user noc", "set system login class p49-readonly-extra permissions all")
	if missing, extra, err := TemplateDrift([]byte(strings.Join(other, "\n")), d, ClassAges{Default: time.Hour}); err != nil ||
		len(missing) != 0 || len(extra) != 0 {
		t.Errorf("other: %q %+v %v", missing, extra, err)
	}
	// A capture that mixes curly form into set form hides what the curly
	// part carries, so it is not read.
	mixed := append(cleanCapture(t, d), "system {", "    login {", `        class p49-readonly { allow-commands ".*"; }`,
		"    }", "}")
	if _, _, err := TemplateDrift([]byte(strings.Join(mixed, "\n")), d, ClassAges{Default: time.Hour}); err == nil ||
		!strings.Contains(err.Error(), "display set") {
		t.Errorf("mixed: %v", err)
	}
	// A prompt, a comment and a blank line are what a captured terminal
	// carries around display set's output.
	session := append([]string{"{master:0}", "admin@srx1> show configuration | display set", "## Last commit: x", "",
		"{master:0}[edit]", "[edit]", "{primary:node0}[edit system login]", "admin@srx1# run show configuration | display set"},
		cleanCapture(t, d)...)
	if missing, extra, err := TemplateDrift([]byte(strings.Join(session, "\n")), d, ClassAges{Default: time.Hour}); err != nil ||
		len(missing) != 0 || len(extra) != 0 {
		t.Errorf("session: %q %+v %v", missing, extra, err)
	}
}

// A level's template is never p49-remote, in any case, and no two templates
// share a class unless they are the same template with the same bits:
// p49-remote is the fallback `remote` user's bitless class, which a session
// whose template the device lacks lands in (L18), so a level under it would
// give every such session that level's bits, and the reference would write
// it and the check pass it (task 13 review I1).
func TestNoTemplateTakesTheRemoteClassOrAnothersClass(t *testing.T) {
	for _, c := range []struct {
		name  string
		names map[string]string
		bits  map[string][]string
	}{
		{"p49-remote", map[string]string{"readonly": "p49-readonly", "admin": "p49-remote"}, nil},
		{"P49-Remote", map[string]string{"readonly": "p49-readonly", "admin": "P49-Remote"}, nil},
		{"a case variant of another template", map[string]string{"readonly": "p49-ops", "admin": "P49-OPS"}, nil},
		{"two levels one class, different bits", map[string]string{"readonly": "p49-ops", "admin": "p49-ops"}, nil},
	} {
		d := junosProjected(BitDeliveryLocalUserName)
		d.LocalUserNames = c.names
		if err := Validate("juniper_junos", d); err == nil {
			t.Errorf("%s: validated", c.name)
		}
		if _, err := ReferenceClasses(d, ClassAges{Default: time.Hour}); err == nil {
			t.Errorf("%s: written", c.name)
		}
		if _, _, err := TemplateDrift([]byte("set system host-name srx1\n"), d, ClassAges{Default: time.Hour}); err == nil {
			t.Errorf("%s: checked", c.name)
		}
	}
	// Two levels with the same bits may share one template, written once.
	d := junosProjected(BitDeliveryLocalUserName)
	d.CeilingBits["operator"] = []string{"all"}
	d.LocalUserNames["operator"] = "p49-admin"
	got, err := ReferenceClasses(d, ClassAges{Default: time.Hour})
	if err != nil || strings.Count(strings.Join(got, "\n"), "delete system login class p49-admin") != 1 {
		t.Errorf("shared: %q %v", got, err)
	}
}

// A path word a hand-edited capture quotes, a curly statement carrying a
// trailing annotation, and a template under a logical system or tenant are
// read as what they are (task 13 review M1-M3).
func TestTemplateDriftReadsQuotedAndNestedPaths(t *testing.T) {
	d := junosProjected(BitDeliveryLocalUserName)
	for _, line := range []string{
		`set system login class "p49-readonly" allow-commands ".*"`,
		`set system login user "p49-admin" authentication encrypted-password "$6$x"`,
		`deactivate "system" login`,
		"set logical-systems ls1 system login class p49-readonly permissions all",
		"set tenants t1 system login class p49-remote permissions all",
	} {
		config := append(cleanCapture(t, d), line)
		if _, extra, err := TemplateDrift([]byte(strings.Join(config, "\n")), d, ClassAges{Default: time.Hour}); err != nil ||
			len(extra) != 1 {
			t.Errorf("%s: %+v %v", line, extra, err)
		}
	}
	mixed := append(cleanCapture(t, d), `system { login { class p49-readonly { allow-commands ".*"; } } } ## x`)
	if _, _, err := TemplateDrift([]byte(strings.Join(mixed, "\n")), d, ClassAges{Default: time.Hour}); err == nil {
		t.Error("an annotated one-line curly statement read as nothing")
	}
	// A group's line is refused, a logical system's included (decision 44
	// ruling 7).
	grouped := append(cleanCapture(t, d), "set groups g logical-systems <*> system login class p49-readonly permissions all")
	if _, _, err := TemplateDrift([]byte(strings.Join(grouped, "\n")), d, ClassAges{Default: time.Hour}); err == nil ||
		!strings.HasPrefix(err.Error(), fmt.Sprintf("line %d ", len(grouped))) {
		t.Errorf("a group's line: %v", err)
	}
}

// The inherited capture prints a group's statements under each template they
// land on and nothing of the group itself (tests/lab/results/L57-juniper_*.md),
// so check-config judges those lines as the template's own: a privilege or
// unlisted statement fails, its finding pointing at the curly form that names
// the group; a harmless one and an apply-groups-except pass. A capture with a
// `set groups` line, or `apply-groups` as a word at any level, was taken
// without `display inheritance` and is refused at that line, quoting nothing
// of it (decision 44 rulings 7 and 9).
func TestTemplateDriftReadsGroups(t *testing.T) {
	d := junosProjected(BitDeliveryUserPermissions)
	const base = "set version 23.4R2-S2.1\nset system login class p49-remote idle-timeout 720\n" +
		"set system login user remote uid 2001\nset system login user remote class p49-remote\n"
	const pointer = "`show configuration system login | display inheritance`"
	for _, c := range []struct {
		name, lines string
		extra       []string // each finding's line, in order, from line 5
	}{
		{"a group's permission and allow-commands, expanded",
			"set system login class p49-remote permissions view-configuration\n" +
				"set system login class p49-remote allow-commands \"^show version$\"\n",
			[]string{"set system login class p49-remote permissions view-configuration",
				`set system login class p49-remote allow-commands "^show version$"`}},
		{"a template user's authentication",
			"set system login user remote authentication encrypted-password \"$6$abc\"\n",
			[]string{`set system login user remote authentication encrypted-password "$6$abc"`}},
		{"a statement on neither list", "set system login class p49-remote allow-hidden-commands\n",
			[]string{"set system login class p49-remote allow-hidden-commands"}},
		{"a harmless word in another case", "set system login class p49-remote Login-Tip\n",
			[]string{"set system login class p49-remote Login-Tip"}},
		{"a user's harmless word on a class", "set system login class p49-remote full-name x\n",
			[]string{"set system login class p49-remote full-name x"}},
		{"a privilege hidden behind a harmless flag", "set system login class p49-remote login-tip permissions all\n",
			[]string{"set system login class p49-remote login-tip permissions all"}},
		{"a privilege hidden behind a harmless value", "set system login class p49-remote idle-timeout 5 permissions all\n",
			[]string{"set system login class p49-remote idle-timeout 5 permissions all"}},
		{"a valueless idle-timeout", "set system login class p49-remote idle-timeout\n",
			[]string{"set system login class p49-remote idle-timeout"}},
		{"a privilege hidden behind an apply-groups-except",
			"set system login class p49-remote apply-groups-except BASE permissions all\n",
			[]string{"set system login class p49-remote apply-groups-except BASE permissions all"}},
		{"a bare template line", "set system login class p49-remote\n",
			[]string{"set system login class p49-remote"}},
		{"harmless", "set system login class p49-remote login-tip\nset system login class p49-remote login-alarms\n" +
			"set system login user remote full-name \"port49 template\"\n", nil},
		{"an apply-groups-except", "set system login class p49-remote apply-groups-except BASE\n" +
			"set system login user remote apply-groups-except BASE\nset system apply-groups-except BASE\n", nil},
		{"a group word in a value", "set interfaces ge-0/0/0 description \"set groups and apply-groups\"\n", nil},
		{"another class", "set system login class noc permissions all\n", nil},
	} {
		missing, extra, err := TemplateDrift([]byte(base+c.lines), d, ClassAges{Default: 12 * time.Hour})
		if err != nil || len(missing) != 0 || len(extra) != len(c.extra) {
			t.Errorf("%s: %v %q %+v", c.name, err, missing, extra)
			continue
		}
		for i, want := range c.extra {
			if e := extra[i]; e.Line != 5+i || e.Text != want || !strings.Contains(e.Says, pointer) {
				t.Errorf("%s: finding %d is %+v, want line %d %q pointing at %s", c.name, i, e, 5+i, want, pointer)
			}
		}
	}
	for _, c := range []struct{ name, lines string }{
		{"a group definition", "set groups BASE system login class <*> permissions all\n"},
		{"a harmless group's definition", "set groups BASE system login class <*> login-tip\n"},
		{"a group quoted", "set \"groups\" BASE system login class <*> login-tip\n"},
		{"a logical system's group", "set logical-systems ls1 groups BASE system login class <*> permissions all\n"},
		{"a tenant's group", "set tenants t1 groups BASE system login class <*> permissions all\n"},
		{"a group applied at the top", "set apply-groups BASE\n"},
		{"a group applied under system", "set system apply-groups BASE\n"},
		{"a group applied on the class", "set system login class p49-remote apply-groups BASE\n"},
		{"a group applied on another class", "set system login class noc apply-groups BASE\n"},
		{"a group applied in a logical system", "set logical-systems ls1 apply-groups BASE\n"},
		{"capitalized", "set system Apply-Groups BASE\n"},
		{"a deactivated application", "deactivate apply-groups BASE\n"},
		{"a group line with a stray quote", "set groups BASE system login class <*> login-tip \"x\n"},
		{"a plain capture, its first sign named", "set groups BASE system login class <*> login-tip\nset apply-groups BASE\n"},
	} {
		_, _, err := TemplateDrift([]byte(base+c.lines+"set system host-name srx1\n"), d, ClassAges{Default: 12 * time.Hour})
		if err == nil || !strings.HasPrefix(err.Error(), "line 5 ") || !strings.Contains(err.Error(), ConfigCapture) ||
			!strings.Contains(err.Error(), "without it") || strings.Contains(err.Error(), "BASE") {
			t.Errorf("%s: want a refusal naming line 5 and %q, quoting nothing of the line: %v", c.name,
				ConfigCapture, err)
		}
	}
}

// The lab's inherited captures (tests/lab/results/L57-juniper_*.md), read as
// each image printed them: p49g-perm's permission and allow-commands, expanded
// under p49-remote, are the only findings, each pointing at the curly form
// that names the group; p49g-tip's login-tip, the excepted group's except
// line and the class's own idle-timeout pass, and the capture is not refused.
// It holds whether or not a regenerated capture carries more harmless lines
// (Task 9 adds a class-level group's login-alarms).
func TestTemplateDriftReadsTheL57Captures(t *testing.T) {
	files, _ := filepath.Glob("testdata/l57-*.set")
	if len(files) != 2 {
		t.Fatalf("want the two L57 captures, got %q", files)
	}
	d := junosProjected(BitDeliveryUserPermissions)
	want := []string{"set system login class p49-remote permissions view-configuration",
		`set system login class p49-remote allow-commands "^show version$"`}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		missing, extra, err := TemplateDrift(raw, d, ClassAges{Default: 12 * time.Hour})
		if err != nil || len(missing) != 0 {
			t.Fatalf("%s: %q %v", f, missing, err)
		}
		var got []string
		for _, e := range extra {
			got = append(got, e.Text)
			if !strings.Contains(e.Says, "| display inheritance") {
				t.Errorf("%s:%d: the finding gives no pointer to the group: %s", f, e.Line, e.Says)
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: findings %q, want %q", f, got, want)
		}
	}
}

// A trailing carriage return is a line ending, so a capture saved with CRLF
// reads as the same capture; a carriage return anywhere else could join two
// statements and is refused.
func TestTemplateDriftReadsCRLF(t *testing.T) {
	d := junosProjected(BitDeliveryLocalUserName)
	clean := strings.Join(cleanCapture(t, d), "\r\n") + "\r\n"
	if missing, extra, err := TemplateDrift([]byte(clean), d, ClassAges{Default: time.Hour}); err != nil || len(missing) != 0 || len(extra) != 0 {
		t.Errorf("crlf: %q %+v %v", missing, extra, err)
	}
	joined := strings.Join(cleanCapture(t, d), "\n") +
		"\nset system login class p49-readonly login-tip\rset system login class p49-readonly permissions all\n"
	line := fmt.Sprintf("line %d ", len(cleanCapture(t, d))+1)
	if _, _, err := TemplateDrift([]byte(joined), d, ClassAges{Default: time.Hour}); err == nil || strings.Contains(err.Error(), "permissions") ||
		!strings.HasPrefix(err.Error(), line) {
		t.Errorf("a mid-line carriage return: %v", err)
	}
	// Exactly one trailing carriage return is a line ending: two are refused.
	doubled := strings.Join(cleanCapture(t, d), "\n") + "\r\r\n"
	if _, _, err := TemplateDrift([]byte(doubled), d, ClassAges{Default: time.Hour}); err == nil || !strings.HasPrefix(err.Error(), "line ") {
		t.Errorf("a doubled carriage return: %v", err)
	}
}

// A class's idle-timeout is held to the rendered minutes as a ceiling: a
// shorter device value carries the line, a longer or missing one does not,
// and a never class (age zero) writes no line and passes any value
// (decision 55 ruling 14).
func TestTemplateDriftHoldsIdleTimeoutAsACeiling(t *testing.T) {
	d := junosProjected(BitDeliveryLocalUserName)
	ages := ClassAges{Default: 12 * time.Hour, ByClass: map[string]time.Duration{"p49-readonly": time.Hour,
		"p49-admin": 0}}
	ref, err := ReferenceClasses(d, ages)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range ref {
		if strings.HasPrefix(l, "set system login class p49-admin idle-timeout") {
			t.Fatalf("a never class carries %q", l)
		}
	}
	capture := func(class, value string) []byte {
		var config []string
		for _, l := range ref {
			if strings.HasPrefix(l, "delete ") {
				continue
			}
			if strings.HasPrefix(l, "set system login class "+class+" idle-timeout") {
				l = "set system login class " + class + " idle-timeout " + value
			}
			config = append(config, l)
		}
		if class == "p49-admin" {
			config = append(config, "set system login class p49-admin idle-timeout "+value)
		}
		return []byte(strings.Join(append(config, "set version 21.4R3"), "\n"))
	}
	for _, c := range []struct {
		class, value string
		missing      int
	}{
		{"p49-readonly", "60", 0}, {"p49-readonly", "30", 0}, {"p49-readonly", "720", 1},
		{"p49-admin", "1", 0}, {"p49-admin", "99999", 0},
	} {
		missing, extra, err := TemplateDrift(capture(c.class, c.value), d, ages)
		if err != nil || len(missing) != c.missing || len(extra) != 0 {
			t.Errorf("%s %s: missing %q extra %+v err %v", c.class, c.value, missing, extra, err)
		}
	}
	if c := capture("p49-readonly", "30"); !strings.Contains(string(c), "idle-timeout 30") {
		t.Fatal("fixture lost the shorter line")
	}
}
