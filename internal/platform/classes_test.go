package platform

import (
	"reflect"
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
	got, err := ReferenceClasses(d, 12*time.Hour+59*time.Second)
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
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%q", got)
	}
	for _, l := range got {
		if strings.Contains(l, "authentication") {
			t.Errorf("a template user that can log in locally: %s", l)
		}
	}
	up, _ := ReferenceClasses(junosProjected(BitDeliveryUserPermissions), 30*time.Second)
	if len(up) != 4 || up[1] != "set system login class p49-remote idle-timeout 1" {
		t.Fatalf("user_permissions: %q", up)
	}
	eos, _ := DialectFor("arista_eos")
	if _, err := ReferenceClasses(eos, time.Hour); err == nil {
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
		if _, err := ReferenceClasses(d, time.Hour); err == nil {
			t.Errorf("%s: written", name)
		}
		if _, _, err := TemplateDrift([]byte("set system host-name srx1\n"), d, time.Hour); err == nil {
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
	ref, _ := ReferenceClasses(d, time.Hour)
	var config []string
	for _, l := range ref {
		if !strings.HasPrefix(l, "delete ") {
			config = append(config, l)
		}
	}
	config = append(config, "set system login user p49-admin uid 2001", "set system host-name srx1")
	missing, extra, err := TemplateDrift([]byte(strings.Join(config, "\n")), d, time.Hour)
	if err != nil || len(missing) != 0 || len(extra) != 0 {
		t.Fatalf("clean: %q %+v %v", missing, extra, err)
	}
	drifted := append(config[1:], `set system login class p49-remote allow-commands "^configure"`,
		`set system login user p49-readonly authentication encrypted-password "$6$x"`,
		"set system login class p49-readonly permissions   clear")
	missing, extra, err = TemplateDrift([]byte(strings.Join(drifted, "\n")), d, time.Hour)
	if err != nil || !reflect.DeepEqual(missing, []string{config[0]}) || len(extra) != 3 ||
		extra[2].Text != "set system login class p49-readonly permissions clear" {
		t.Fatalf("drift: %q %+v %v", missing, extra, err)
	}
	if _, _, err := TemplateDrift([]byte("system {\n  login {\n  }\n}\n"), d, time.Hour); err == nil ||
		!strings.Contains(err.Error(), "display set") {
		t.Fatalf("curly form: %v", err)
	}
}

// cleanCapture is the reference as `display set` prints it once loaded.
func cleanCapture(t *testing.T, d Dialect) []string {
	t.Helper()
	ref, err := ReferenceClasses(d, time.Hour)
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
// a configuration group that sets one, and a curly-form section a capture
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
		{"a group applied to the class", "set system login class p49-readonly apply-groups wide", false},
		{"a group setting a template class", `set groups wide system login class p49-readonly allow-commands ".*"`,
			false},
		{"a wildcard group", "set groups wide system login class <p49-*> permissions all", false},
		{"a wildcard group above", "set groups wide system login <*> p49-readonly permissions all", false},
		{"a deactivated idle-timeout", "deactivate system login class p49-admin idle-timeout", false},
		{"a deactivated class", "deactivate system login class p49-readonly", false},
		{"a deactivated login", "deactivate system login", false},
	} {
		config := append(cleanCapture(t, d), c.line)
		missing, extra, err := TemplateDrift([]byte(strings.Join(config, "\n")), d, time.Hour)
		if err != nil || len(extra) != 1 || extra[0].Line != len(config) || len(missing) != 0 {
			t.Errorf("%s: %q %+v %v", c.name, missing, extra, err)
		}
	}
	// A timeout the reference does not write is both: the reference's line
	// missing and the device's extra.
	config := cleanCapture(t, d)
	for i, l := range config {
		if l == "set system login class p49-admin idle-timeout 60" {
			config[i] = "set system login class p49-admin idle-timeout 100000"
		}
	}
	missing, extra, err := TemplateDrift([]byte(strings.Join(config, "\n")), d, time.Hour)
	if err != nil || !reflect.DeepEqual(missing, []string{"set system login class p49-admin idle-timeout 60"}) ||
		len(extra) != 1 {
		t.Errorf("idle-timeout: %q %+v %v", missing, extra, err)
	}
	// Lines under other classes, users and groups are not the check's.
	other := append(cleanCapture(t, d), "set system login class noc permissions all",
		"set system login user noc class super-user", "set groups wide system login user noc full-name x",
		"deactivate system login user noc", "set system login class p49-readonly-extra permissions all")
	if missing, extra, err := TemplateDrift([]byte(strings.Join(other, "\n")), d, time.Hour); err != nil ||
		len(missing) != 0 || len(extra) != 0 {
		t.Errorf("other: %q %+v %v", missing, extra, err)
	}
	// A capture that mixes curly form into set form hides what the curly
	// part carries, so it is not read.
	mixed := append(cleanCapture(t, d), "system {", "    login {", `        class p49-readonly { allow-commands ".*"; }`,
		"    }", "}")
	if _, _, err := TemplateDrift([]byte(strings.Join(mixed, "\n")), d, time.Hour); err == nil ||
		!strings.Contains(err.Error(), "display set") {
		t.Errorf("mixed: %v", err)
	}
	// A prompt, a comment and a blank line are what a captured terminal
	// carries around display set's output.
	session := append([]string{"{master:0}", "admin@srx1> show configuration | display set", "## Last commit: x", ""},
		cleanCapture(t, d)...)
	if missing, extra, err := TemplateDrift([]byte(strings.Join(session, "\n")), d, time.Hour); err != nil ||
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
		if _, err := ReferenceClasses(d, time.Hour); err == nil {
			t.Errorf("%s: written", c.name)
		}
		if _, _, err := TemplateDrift([]byte("set system host-name srx1\n"), d, time.Hour); err == nil {
			t.Errorf("%s: checked", c.name)
		}
	}
	// Two levels with the same bits may share one template, written once.
	d := junosProjected(BitDeliveryLocalUserName)
	d.CeilingBits["operator"] = []string{"all"}
	d.LocalUserNames["operator"] = "p49-admin"
	got, err := ReferenceClasses(d, time.Hour)
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
		"set groups g logical-systems <*> system login class p49-readonly permissions all",
	} {
		config := append(cleanCapture(t, d), line)
		if _, extra, err := TemplateDrift([]byte(strings.Join(config, "\n")), d, time.Hour); err != nil ||
			len(extra) != 1 {
			t.Errorf("%s: %+v %v", line, extra, err)
		}
	}
	mixed := append(cleanCapture(t, d), `system { login { class p49-readonly { allow-commands ".*"; } } } ## x`)
	if _, _, err := TemplateDrift([]byte(strings.Join(mixed, "\n")), d, time.Hour); err == nil {
		t.Error("an annotated one-line curly statement read as nothing")
	}
}
