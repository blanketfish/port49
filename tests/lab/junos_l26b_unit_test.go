//go:build lab

package lab

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// These run without a device: the L26b classifiers and the denies it renders.

func TestL26bCell(t *testing.T) {
	screen := regexp.MustCompile(`Screen length set to 0`)
	for _, c := range []struct {
		out  string
		ev   *regexp.Regexp
		want string
	}{
		{"show cli | count \nCount: 9 lines\nalice01@srx1> ", nil, "ran"},
		{"show policy | count \nCount: 0 lines\n", nil, "ran"},
		{"show cli | count \n         ^\npermission denied.\n", nil, "refused"},
		{"show configuration vlans | count\n                   ^\nsyntax error.\n", nil, "refused"},
		{"save dhcp\n^\nunknown command.\n", nil, "refused"},
		{"set cli screen-length 0 \nScreen length set to 0\n", screen, "ran"},
		// Neither the evidence nor a refusal: not observed.
		{"show task memory | count \n", nil, "not observed"},
		{"", nil, "not observed"},
		// Both: not observed, never a run nor a refusal.
		{"Count: 1 lines\nsyntax error.", nil, "not observed"},
	} {
		if got := l26bCell(c.out, c.ev); got != c.want {
			t.Errorf("l26bCell(%q) = %q, want %q", c.out, got, c.want)
		}
	}
}

func TestL26bVerdict(t *testing.T) {
	unknown := "save\n              ^\nunknown command.\n"
	argument := "                                       ^\nsyntax error, expecting <command>.\n"
	for _, c := range []struct {
		control, deny string
		offered       bool
		out           string
		want          string
	}{
		{"ran", "refused", true, "", "proven"},
		{"ran", "refused", false, "", "proven"}, // a hidden word the control runs
		{"ran", "ran", true, "", "unproven"},
		{"ran", "not observed", true, "", "unproven"},
		{"not observed", "refused", true, "", "unproven"},
		{"refused", "refused", false, unknown, "absent"},
		{"refused", "not observed", false, unknown, "absent"},
		// A refusal of the argument after a hidden head is not absence.
		{"refused", "not observed", false, argument, "unproven"},
		{"refused", "refused", true, unknown, "unproven"}, // offered, and the control could not run it
		{"not observed", "refused", false, unknown, "unproven"},
	} {
		if got := l26bVerdict(c.control, c.deny, c.offered, c.out); got != c.want {
			t.Errorf("l26bVerdict(%q, %q, %v, %q) = %q, want %q", c.control, c.deny, c.offered, c.out, got, c.want)
		}
	}
}

func TestL26bDenies(t *testing.T) {
	if got, want := l26bDeny("show", []string{"cli", "host"}), ` *show +(cli|host)( .*)? *(\|.*)?`; got != want {
		t.Errorf("l26bDeny = %q, want %q", got, want)
	}
	if got, want := l26bDeny("", []string{"exit"}), ` *exit( .*)? *(\|.*)?`; got != want {
		t.Errorf("l26bDeny root = %q, want %q", got, want)
	}
	re := regexp.MustCompile("^(" + l26bDeny("show configuration", []string{"system", "interfaces"}) + ")$")
	for cmd, want := range map[string]bool{"show configuration system": true, "show configuration system | count": true,
		"  show  configuration interfaces ge-0/0/0": true, "show configuration": false, "show configuration systems": false} {
		if re.MatchString(cmd) != want {
			t.Errorf("%q: matched %v", cmd, !want)
		}
	}
	chunks := l26bChunks("show configuration", junosL26bHierarchies)
	var all []string
	for _, ch := range chunks {
		if n := len("deny-commands=^(" + l26bDeny("show configuration", ch) + ")$"); n > 255 {
			t.Errorf("a chunk is %d bytes", n)
		}
		all = append(all, ch...)
	}
	if !slices.Equal(all, junosL26bHierarchies) {
		t.Errorf("the chunks lose or reorder words: %v", all)
	}
	t.Logf("%d hierarchy denies: %s", len(chunks), strings.Repeat("·", len(chunks)))
}

// junosL26bOffered is what each image's completion offered at the root and
// after `show configuration` (the run's break-glass listings; the survey,
// tests/lab/logs), for the note re-reads below.
var junosL26bOffered = map[string]map[string][]string{
	"juniper_vjunos-router": {
		"":                   {"save"},
		"show configuration": {"access", "access-profile", "accounting-options", "applications", "apply-groups", "bridge-domains", "chassis", "class-of-service", "diameter", "dynamic-profiles", "event-options", "firewall", "forwarding-options", "groups", "interfaces", "jsrc", "jsrc-partition", "logical-systems", "multi-chassis", "multicast-snooping-options", "poe", "policy-options", "protocols", "routing-instances", "routing-options", "security", "services", "snmp", "switch-options", "system", "unified-edge", "virtual-chassis"},
	},
	"juniper_vsrx": {
		"":                   {},
		"show configuration": {"access", "access-profile", "accounting-options", "applications", "apply-groups", "chassis", "class-of-service", "diameter", "event-options", "firewall", "forwarding-options", "groups", "interfaces", "policy-options", "protocols", "routing-instances", "routing-options", "schedulers", "security", "services", "smtp", "snmp", "switch-options", "system", "vlans"},
	},
}

// TestCommittedL26bVerdictsHold re-reads both committed L26b notes: every
// row's control and deny cells, recomputed from the recorded outputs (but
// `exit`'s, which is the session ending, not an output), and every verdict.
func TestCommittedL26bVerdictsHold(t *testing.T) {
	block := regexp.MustCompile("(?s)\n#### `([^`\n]+)`\n\ncontrol:\n\n```\n(.*?)\n```\n\ndeny:\n\n```\n(.*?)\n```\n")
	for img, offered := range junosL26bOffered {
		raw, err := os.ReadFile(filepath.Join("results", "L26b-"+img+".md"))
		if err != nil {
			t.Fatal(err)
		}
		note := string(raw)
		outs := map[string][2]string{}
		for _, m := range block.FindAllStringSubmatch(note, -1) {
			outs[m[1]] = [2]string{m[2], m[3]}
		}
		words := slices.Clone(junosL26bShowWords)
		words = append(words, junosL26bRootWords...)
		for _, h := range junosL26bHierarchies {
			words = append(words, l26bWord{path: "show configuration", word: h, cmd: "show configuration " + h + " | count"})
		}
		for _, w := range words {
			row := tableRow(note, "`"+w.path+"`")
			for _, line := range strings.Split(note, "\n") {
				if strings.HasPrefix(line, "| `"+w.path+"` | `"+w.word+"` |") {
					row = strings.Split(strings.Trim(strings.ReplaceAll(line, `\|`, "\x00"), "| "), " | ")
				}
			}
			o, ok := outs[w.cmd]
			if !ok || len(row) < 6 {
				t.Errorf("%s: no row or outputs for %q", img, w.cmd)
				continue
			}
			cc, dc := l26bCell(o[0], w.evidence), l26bCell(o[1], w.evidence)
			isOffered := slices.Contains(offered[w.path], w.word) || w.path == "show" || w.path == "set"
			v := l26bVerdict(cc, dc, isOffered, o[0])
			got := strings.Trim(strings.Fields(row[5])[0], "*")
			if cc != row[3] || dc != row[4] || v != got {
				t.Errorf("%s %q after %q: the note reads %s / %s / %s, the classifier now %s / %s / %s", img, w.word,
					w.path, row[3], row[4], got, cc, dc, v)
			}
		}
	}
}
