package projection

import (
	"errors"
	"regexp"
	"testing"
)

func TestRuleERE(t *testing.T) {
	classes := map[string][]string{"management": {"^(fxp0|em0)$"}, "uplink": {"^et-0/0/[0-3]$", "^ae1$"}}
	folded := Facts{CaseSensitive: true}
	for _, c := range []struct {
		rule string
		deny bool
		want string
	}{
		{"show version", false, "show version"},
		{"show version", true, `[sS][hH][oO][wW] +[vV][eE][rR][sS][iI][oO][nN]( *\|.*)?`},
		{"SHOW Version", false, "show version"},
		{"show interfaces **", false, "show interfaces( .*)?"},
		{"**", false, ".*"},
		{"show route *", false, "show route [^ ]+"},
		{"show route *", true, `[sS][hH][oO][wW] +[rR][oO][uU][tT][eE] +.+( *\|.*)?`},
		{"file show /var/log/messages", false, `file show /var/log/messages`},
		{"ping 10.0.0.1", false, `ping 10\.0\.0\.1`},
		{"show interfaces @management", false, "show interfaces ((fxp0|em0))"},
		{"show interfaces @uplink **", false, "show interfaces ((et-0/0/[0-3])|(ae1))( .*)?"},
		{"show interfaces /^ge-/", false, "show interfaces (ge-)[^ ]*"},
		{"show interfaces /ge-/", true, `[sS][hH][oO][wW] +[iI][nN][tT][eE][rR][fF][aA][cC][eE][sS] +.*([gG][eE]-).*( *\|.*)?`},
	} {
		got, err := ruleERE(c.rule, classes, c.deny, folded)
		if err != nil || got != c.want {
			t.Errorf("ruleERE(%q, deny=%v) = %q, %v; want %q", c.rule, c.deny, got, err, c.want)
		}
	}
	for _, rule := range []string{"echo {username}", `show "x"`, "show /\\bword/", "show café",
		"show /^(ge|)$/", "show /^()$/", "show /^$/"} {
		if _, err := ruleERE(rule, classes, true, folded); err == nil {
			t.Errorf("ruleERE(%q) wrote it", rule)
		}
	}
	// A class's bracket expression is POSIX: `]` first, `-` last, ranges
	// for runs.
	got, err := ruleERE("show interfaces /^[a-c\\]-]x$/", nil, false, Facts{})
	if err != nil || got != "show interfaces ([]A-Ca-c-]x)" {
		t.Errorf("bracket: %q %v", got, err)
	}
}

// The ERE a deny is written as matches every spelling of the rule's words
// port49 matches, in either case, and nothing past the rule's own shape: a
// check with Go's regexp, which reads this subset of ERE the same way.
func TestADenyERECoversEveryCase(t *testing.T) {
	e, err := ruleERE("show configuration **", nil, true, Facts{CaseSensitive: true})
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile("^" + e + "$")
	for line, want := range map[string]bool{"show configuration": true, "SHOW Configuration system": true,
		"show configurations": false, "request show configuration": false} {
		if re.MatchString(line) != want {
			t.Errorf("%q: %v", line, !want)
		}
	}
	if _, err := ruleERE("show é", nil, true, Facts{}); !errors.Is(err, errUnwritable) {
		t.Errorf("non-ASCII: %v", err)
	}
}

// A deny matches every line port49 denies under its rule, in every spelling
// the device may be handed: a pipeline after it, a run of spaces between
// words, and a quoted argument that holds a space. An allow matches only the
// rule's own narrow shape.
func TestADenyEREIsWideAndAnAllowNarrow(t *testing.T) {
	for _, c := range []struct {
		rule  string
		deny  bool
		lines map[string]bool
	}{
		{"clear bgp all", true, map[string]bool{"clear bgp all": true, "clear bgp all | no-more": true,
			"clear bgp all|count": true, "clear  bgp all": true, "clear bgp all x": false}},
		{"show route *", true, map[string]bool{`show route "a b"`: true, "show route": false}},
		{"show interfaces @spaced", true, map[string]bool{"show interfaces ge 0": true}},
		{"show interfaces /^[a-z{]+$/", true, map[string]bool{"show interfaces a{b": true}},
		{"show route *", false, map[string]bool{"show route x": true, `show route "a b"`: false,
			"show route x | no-more": false, "show  route x": false}},
	} {
		e, err := ruleERE(c.rule, map[string][]string{"spaced": {"^[a-z ]+$"}}, c.deny, Facts{CaseSensitive: true})
		if err != nil {
			t.Fatalf("%s: %v", c.rule, err)
		}
		re := regexp.MustCompile("^" + e + "$")
		for line, want := range c.lines {
			if re.MatchString(line) != want {
				t.Errorf("%s (deny=%v) against %q: %v", c.rule, c.deny, line, !want)
			}
		}
	}
}
