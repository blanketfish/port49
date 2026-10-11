//go:build lab

package lab

import (
	"errors"
	"strings"
	"testing"
)

// These run without a device: L57's capture readings and nested-group cell,
// and the withholding of a secret from junosTryConfigure's errors.

func TestL57ReadingsApplyGroupsAtAnyLevel(t *testing.T) {
	for _, c := range []struct {
		name, line string
		want       bool
	}{
		{"top", "set apply-groups p49g-tip", true},
		{"system", "set system apply-groups p49g-tip", true},
		{"class", "set system login class p49-remote apply-groups p49g-classlevel", true},
		{"except", "set system login class p49-remote apply-groups-except p49g-excepted", false},
		{"none", "set system login class p49-remote login-tip hi", false},
	} {
		r := l57Readings("set system host-name x\n" + c.line + "\n")
		if r.applyLines != c.want {
			t.Errorf("%s: applyLines %v, want %v", c.name, r.applyLines, c.want)
		}
		if !r.parsed {
			t.Errorf("%s: not parsed", c.name)
		}
	}
	if l57Readings("set groups g system x\n").groupLines != true {
		t.Error("a set groups line was not read")
	}
}

func TestL57CurlyIsNotParsed(t *testing.T) {
	r := l57Readings("system {\n    login {\n        class p49-remote {\n            login-tip hi;\n        }\n    }\n}\n")
	if r.parsed {
		t.Fatal("curly text read as parsed")
	}
	if got := l57Cell(r, false); got != "not parsed" {
		t.Errorf("curly cell %q", got)
	}
	if got := l57Cell(l57Readings("set a b\n"), false); got != "no" {
		t.Errorf("set cell %q", got)
	}
}

func TestL57NestedCell(t *testing.T) {
	ok := func(auth string) junosRun {
		return junosRun{auth: auth, outs: map[string]string{l57ControlCmd: "host-name srx1;"}}
	}
	refused := ok("syntax error, expecting <command>.")
	noControl := ok("Current user: x")
	noControl.outs[l57ControlCmd] = "error: permission denied"
	unobs := ok("Current user: x")
	unobs.unobserved = []string{"show cli authorization"}
	for _, c := range []struct {
		name   string
		run    junosRun
		opened bool
		want   string
	}{
		{"applies", ok("Current user: x"), true, "applies"},
		{"not applied", refused, true, "not applied"},
		{"control refused", noControl, true, "not observed"},
		{"unobserved", unobs, true, "not observed"},
		{"no session", ok("Current user: x"), false, "not observed"},
		{"empty", ok(" "), true, "not observed"},
	} {
		if got := l57NestedCell(c.run, c.opened); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestJunosTryErrorWithholds(t *testing.T) {
	const hash = "$6$saltsalt$ABCDEFsecretsecret"
	lines := []string{`set system root-authentication encrypted-password "` + hash + `"`}
	ferr := errors.New(lines[0] + " was refused by the device:\n" + lines[0])
	for _, err := range []error{
		junosTryError(lines, "system root-authentication", ferr, lines[0]),
		junosRollbackError(lines, "system root-authentication", ferr, ferr),
	} {
		if strings.Contains(err.Error(), "$6$") || strings.Contains(err.Error(), "secretsecret") {
			t.Errorf("the withheld error holds the hash: %v", err)
		}
		if !strings.Contains(err.Error(), "system root-authentication") {
			t.Errorf("the withheld error does not name the statement: %v", err)
		}
	}
	if err := junosTryError([]string{"set a b"}, "", errors.New("boom"), "out"); !strings.Contains(err.Error(), "set a b") {
		t.Errorf("the plain error lost the lines: %v", err)
	}
}
