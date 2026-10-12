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

// l57Auth is a `show cli authorization` as the device prints it, with the
// permission names given, each followed by a description that holds words such
// as "network" (clear's: "Can clear learned network info").
func l57Auth(perms ...string) string {
	desc := map[string]string{
		"clear":              "Can clear learned network info",
		"view":               "Can view current values and statistics",
		"view-configuration": "Can view all configuration (not including secrets)",
		"network":            "Can access the network",
	}
	out := "Current user: 'p49-l57own' login: 'alice02' class 'p49-l57own'\nPermissions:\n"
	for _, p := range perms {
		out += "    " + p + "       -- " + desc[p] + "\n"
	}
	return out + "\nIndividual command authorization:\n    Allow regular expression: ^show version$\n" +
		"    Deny regular expression: none\n\nalice02@srx1> "
}

func TestL57NestedCell(t *testing.T) {
	const prompt = len("alice02@srx1> ")
	ran := "PING 127.0.0.1 (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0\n\n" +
		"--- 127.0.0.1 ping statistics ---\n1 packets transmitted, 1 packets received, 0% packet loss\n"
	refusedPing := strings.Repeat(" ", prompt+len("ping")) + "^\nunknown command.\n"
	session := func(auth, ping string) junosRun {
		r := junosRun{user: "alice02", auth: auth, outs: map[string]string{}}
		if ping != "" {
			r.outs[l57PingCmd] = ping
		}
		return r
	}
	controls := []string{"clear", "view", "view-configuration"}
	applies := session(l57Auth(append(controls, "network")...), ran)
	notApplied := session(l57Auth(controls...), refusedPing)
	noClear := session(l57Auth("view", "view-configuration"), refusedPing)
	noVC := session(l57Auth("clear", "view"), refusedPing)
	// `network` named only in a description, never as a permission.
	descOnly := session(l57Auth(controls...), refusedPing)
	descOnly.auth = strings.Replace(descOnly.auth, "Can clear learned network info", "Can clear learned network info; network", 1)
	authDisagrees := session(l57Auth(append(controls, "network")...), refusedPing)
	pingDisagrees := session(l57Auth(controls...), ran)
	noPing := session(l57Auth(controls...), "")
	unobsPing := session(l57Auth(controls...), refusedPing)
	unobsPing.unobserved = []string{l57PingCmd}
	pingOther := session(l57Auth(controls...), "some other output\n")
	unobsAuth := session(l57Auth(controls...), refusedPing)
	unobsAuth.unobserved = []string{"show cli authorization"}
	loginErr := session("", "")
	loginErr.loginErr = "refused"
	noCurrent := session("syntax error, expecting <command>.", refusedPing)
	empty := session(" ", "")
	for _, c := range []struct {
		name   string
		own    junosRun
		opened bool
		want   string
	}{
		{"applies: network listed, ping ran", applies, true, "applies"},
		{"not applied: controls listed, no network, ping refused", notApplied, true, "not applied"},
		{"network only in a description", descOnly, true, "not applied"},
		{"clear missing: top-level groups did not reach", noClear, true, "not observed"},
		{"view-configuration missing", noVC, true, "not observed"},
		{"network listed, ping refused", authDisagrees, true, "not observed"},
		{"network absent, ping ran", pingDisagrees, true, "not observed"},
		{"ping not typed", noPing, true, "not observed"},
		{"ping unobserved", unobsPing, true, "not observed"},
		{"ping neither ran nor refused", pingOther, true, "not observed"},
		{"authorization unobserved", unobsAuth, true, "not observed"},
		{"login error", loginErr, true, "not observed"},
		{"no session", applies, false, "not observed"},
		{"no Current user", noCurrent, true, "not observed"},
		{"empty", empty, true, "not observed"},
	} {
		if got := l57NestedCell(c.own, c.opened); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

func TestL57Permissions(t *testing.T) {
	got := l57Permissions(l57Auth("clear", "view", "network"))
	if strings.Join(got, ",") != "clear,view,network" {
		t.Errorf("permissions %v", got)
	}
	if len(l57Permissions("syntax error")) != 0 {
		t.Error("a refusal read as holding permissions")
	}
}

// r.nested is the inner group's `permissions network` under p49-remote and
// nothing else, `view` included (p49-remote holds view-configuration alone).
func TestL57ReadsTheNestedGroup(t *testing.T) {
	if !l57Readings("set system login class p49-remote permissions network\n").nested {
		t.Error("the nested group's permissions network was not read")
	}
	for _, ln := range []string{"set system login class p49-remote permissions view\n",
		"set system login class p49-remote permissions view-configuration\n",
		"set system login class noc permissions network\n"} {
		if l57Readings(ln).nested {
			t.Errorf("%q read as the nested group", ln)
		}
	}
}

// p49g-classlevel adds login-alarms under <p49-*>, so its expansion is a
// login-alarms line under p49-remote, and only there.
func TestL57ReadsTheClassLevelGroup(t *testing.T) {
	if !l57Readings("set system login class p49-remote login-alarms\n").classLevel {
		t.Error("p49g-classlevel's login-alarms under p49-remote was not read")
	}
	if l57Readings("set system login class noc login-alarms\n").classLevel {
		t.Error("another class's login-alarms was read as p49-remote's")
	}
	if !l57Readings("set system login class p49-remote apply-groups p49g-classlevel\n").classApply {
		t.Error("the class's own apply-groups line was not read")
	}
	if l57Readings("set system login class p49-remote apply-groups-except p49g-classlevel\n").classApply {
		t.Error("an apply-groups-except line was read as the class's apply-groups")
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
