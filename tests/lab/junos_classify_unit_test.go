//go:build lab

package lab

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// These run without a device: the Task 3b classifiers, each branch, and the
// replies the committed notes recorded, read again by the classifiers as they
// stand, so a classifier change that would move a committed verdict fails
// here before any lab run.

func TestNetconfCell(t *testing.T) {
	const ev = "host-name"
	for _, c := range []struct{ reply, want string }{
		{"<rpc-reply><configuration><system><host-name>srx1</host-name></system></configuration></rpc-reply>", "ran"},
		// A warning beside the output is a run.
		{"<rpc-reply><rpc-error><error-severity>warning</error-severity><error-message>missing mandatory statement(s)" +
			"</error-message></rpc-error><configuration><host-name>srx1</host-name></configuration></rpc-reply>", "ran"},
		{"<rpc-reply><rpc-error>\n<error-type>protocol</error-type>\n<error-severity>error</error-severity>\n" +
			"<error-message>permission denied</error-message>\n</rpc-error></rpc-reply>", "refused"},
		// A warning alone refuses nothing.
		{"<rpc-reply><rpc-error><error-severity>warning</error-severity></rpc-error></rpc-reply>", "not observed"},
		{"<rpc-reply><ok/></rpc-reply>", "not observed"},
		{"", "not observed"},
	} {
		if got := netconfCell(c.reply, ev); got != c.want {
			t.Errorf("netconfCell(%.60q) = %q, want %q", c.reply, got, c.want)
		}
	}
}

func TestNetconfDialCell(t *testing.T) {
	closed := errors.New("alice03: the device sent no NETCONF hello: the NETCONF channel closed: EOF (); port49d recorded [...]")
	for _, c := range []struct {
		err                  error
		authorized, isolated bool
		want                 string
	}{
		{closed, true, true, junosNetconfClosed},
		{closed, false, true, "not observed"}, // closed before port49d authorized anything
		{closed, true, false, "not observed"}, // no paired control proved it opens
		{errors.New("the device sent no NETCONF hello: no NETCONF end-of-message marker within 45s"), true, true, "not observed"},
		{errors.New("SSH to the NETCONF port 830: dial tcp 172.100.100.21:830: i/o timeout"), true, true, "not observed"},
		{errors.New("request the netconf subsystem on port 830: ssh: subsystem request failed"), true, true, "not observed"},
		{errors.New("ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain"),
			false, true, "login refused"},
	} {
		if got := netconfDialCell(c.err, c.authorized, c.isolated); got != c.want {
			t.Errorf("netconfDialCell(%q, %v, %v) = %q, want %q", c.err, c.authorized, c.isolated, got, c.want)
		}
	}
}

func TestAbbrevCells(t *testing.T) {
	ver := junosAbbrevProbe{cmd: "sh ver", of: "show version"}
	count := junosAbbrevProbe{cmd: "sh int ter | count", of: "show interfaces terse"}
	for _, c := range []struct {
		p                  junosAbbrevProbe
		control, deny      string
		wantCtrl, wantDeny string
	}{
		{ver, "show version\nHostname: srx1\nJunos: 23.4R2-S2.1", "show version\n  ^\npermission denied.", "ran", "refused"},
		{ver, "show version\nJunos: 23.4", "show version\nJunos: 23.4", "ran", "ran"},
		{junosAbbrevProbe{cmd: "sh int ter", of: "show interfaces terse"},
			"show interfaces terse\nInterface               Admin Link Proto", "show interfaces ter\nerror: device ter not found",
			"ran", "not run"},
		{junosAbbrevProbe{cmd: "sh i terse", of: "show interfaces terse"}, "show i\n'i' is ambiguous.",
			"show i\n'i' is ambiguous.", "ambiguous", "ambiguous"},
		// Neither the output nor an error: not observed, never safe.
		{ver, "show version\nJunos: 23.4", "show version\n", "ran", "not observed"},
		// `| count`: one line is an error's; the control's count is a run; another count is not observed.
		{count, "show interfaces terse | count\nCount: 42 lines", "show interfaces ter | count\nCount: 1 lines", "ran", "not run"},
		{count, "Count: 42 lines", "Count: 42 lines", "ran", "ran"},
		{count, "Count: 42 lines", "Count: 23 lines", "ran", "not observed"},
		{count, "Count: 1 lines", "Count: 1 lines", "not run", "not run"},
		{count, "Count: 42 lines", "show interfaces terse | count\n  ^\npermission denied.", "ran", "refused"},
	} {
		cc, dc := abbrevCells(c.p, c.control, c.deny)
		if cc != c.wantCtrl || dc != c.wantDeny {
			t.Errorf("%q: (%q, %q) = %q, %q; want %q, %q", c.p.cmd, oneLine(c.control), oneLine(c.deny), cc, dc,
				c.wantCtrl, c.wantDeny)
		}
	}
	if got := expansion("\a\a\ashow interfaces terse \nInterface"); got != "show interfaces terse" {
		t.Errorf("expansion trims the bell: %q", got)
	}
}

// noteBlocks reads a note's per-session output blocks: under each `### <name>`
// heading, "`<label>`:" followed by a fenced block.
func noteBlocks(t *testing.T, note string) map[string]map[string]string {
	t.Helper()
	heading := regexp.MustCompile(`(?m)^### (.+)$`)
	block := regexp.MustCompile("(?s)\n`([^`\n]+)`:\n\n```\n(.*?)\n```\n")
	out := map[string]map[string]string{}
	locs := heading.FindAllStringSubmatchIndex(note, -1)
	for i, l := range locs {
		end := len(note)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		name := note[l[2]:l[3]]
		out[name] = map[string]string{}
		for _, m := range block.FindAllStringSubmatch(note[l[1]:end], -1) {
			out[name][m[1]] = m[2]
		}
	}
	return out
}

// tableRow is the cells of the note's table row that begins with first.
func tableRow(note, first string) []string {
	for _, line := range strings.Split(note, "\n") {
		if !strings.HasPrefix(line, "| "+first+" |") {
			continue
		}
		cells := regexp.MustCompile(` \| `).Split(strings.Trim(strings.ReplaceAll(line, `\|`, "\x00"), "| "), -1)
		for i := range cells {
			cells[i] = strings.ReplaceAll(cells[i], "\x00", "|")
		}
		return cells
	}
	return nil
}

// baseCell is the outcome a note's cell records, its qualifiers dropped.
func baseCell(cell string) string {
	switch {
	case strings.HasPrefix(cell, "not isolated ("):
		return strings.TrimSuffix(strings.TrimPrefix(cell, "not isolated ("), ")")
	case strings.HasPrefix(cell, "not counted:"):
		i := strings.LastIndex(cell, "(here: ")
		return strings.TrimSuffix(cell[i+len("(here: "):], ")")
	}
	before, _, _ := strings.Cut(cell, ";")
	return before
}

func TestCommittedL9VerdictsHold(t *testing.T) {
	for _, img := range []string{"juniper_vjunos-router", "juniper_vsrx"} {
		raw, err := os.ReadFile(filepath.Join("results", "L9-abbreviations-"+img+".md"))
		if err != nil {
			t.Fatal(err)
		}
		note := string(raw)
		blocks := noteBlocks(t, note)
		for _, p := range junosAbbrevProbes {
			row := tableRow(note, tableCell(fmt.Sprintf("%q", p.cmd)))
			if row == nil {
				t.Errorf("%s: no row for %q", img, p.cmd)
				continue
			}
			cc, dc := abbrevCells(p, blocks["control"][p.cmd], blocks["deny"][p.cmd])
			if cc != row[1] || dc != baseCell(row[2]) {
				t.Errorf("%s %q: the note reads %q / %q, the classifier now %q / %q", img, p.cmd, row[1], row[2], cc, dc)
			}
		}
		if !strings.Contains(note, "JunosFacts.DenyMatchesExpanded (keywords) = true") ||
			!strings.Contains(note, "enforced: true") {
			t.Errorf("%s: the committed read-off is not the one this test re-derives", img)
		}
	}
}

func TestCommittedNetconfVerdictsHold(t *testing.T) {
	for _, img := range []string{"juniper_vjunos-router", "juniper_vsrx"} {
		raw, err := os.ReadFile(filepath.Join("results", "L12-netconf-"+img+".md"))
		if err != nil {
			t.Fatal(err)
		}
		note := string(raw)
		blocks := noteBlocks(t, note)
		for _, v := range junosNetconfVariants {
			row := tableRow(note, v.name)
			if row == nil {
				t.Fatalf("%s: no row for %q", img, v.name)
			}
			for k, r := range junosNetconfRPCs {
				reply := blocks[v.name][r.rpc]
				want := baseCell(row[3+k])
				got := netconfCell(reply, r.evidence)
				if rest, ok := strings.CutPrefix(reply, "no session: "); ok {
					errText, _, _ := strings.Cut(rest, "\n")
					got = netconfDialCell(errors.New(errText), strings.Contains(rest, "authorize_session"),
						strings.Contains(rest, "paired control before") && strings.Contains(rest, "paired control after") &&
							!strings.Contains(rest, "no hello"))
				}
				if got != want {
					t.Errorf("%s %s %s: the note reads %q, the classifier now %q", img, v.name, r.rpc, want, got)
				}
			}
		}
		if !strings.Contains(note, "bind NETCONF RPCs: false") {
			t.Errorf("%s: the committed read-off is not `false`", img)
		}
	}
}

func TestAskingForCommand(t *testing.T) {
	for _, c := range []struct {
		out  string
		want bool
	}{
		{"show chassis | display xml rpc\n                                 ^\nsyntax error, expecting <command>.\n", true},
		{"show route foo | display xml rpc\n           ^\nsyntax error, expecting <command>: foo\n", false},
		{"show chassis\nsyntax error, expecting <command>.\nsyntax error, expecting <command>: bar", false},
		{"show interfaces fxp0 | display xml rpc\n<rpc><get-interface-information>", false},
		{"error: syntax error, expecting <argument>", false},
	} {
		if got := askingForCommand(c.out); got != c.want {
			t.Errorf("askingForCommand(%q) = %v, want %v", c.out, got, c.want)
		}
	}
}
