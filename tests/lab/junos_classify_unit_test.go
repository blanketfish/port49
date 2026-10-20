//go:build lab

package lab

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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
	// The control's own run of `show interfaces terse`: three lines as
	// `| count` counts them (the blank line and the prompt are not).
	plain := " \nInterface               Admin Link Proto    Local                 Remote\ncbp0  up  up\nfxp0  up  up\n\nalice01@srx1> "
	for _, c := range []struct {
		p                    junosAbbrevProbe
		control, deny, plain string
		wantCtrl, wantDeny   string
	}{
		{ver, "show version\nHostname: srx1\nJunos: 23.4R2-S2.1", "show version\n  ^\npermission denied.", "", "ran", "refused"},
		{ver, "show version\nJunos: 23.4", "show version\nJunos: 23.4", "", "ran", "ran"},
		{junosAbbrevProbe{cmd: "sh int ter", of: "show interfaces terse"},
			"show interfaces terse\nInterface               Admin Link Proto", "show interfaces ter\nerror: device ter not found", "",
			"ran", "not run"},
		{junosAbbrevProbe{cmd: "sh i terse", of: "show interfaces terse"}, "show i\n'i' is ambiguous.",
			"show i\n'i' is ambiguous.", "", "ambiguous", "ambiguous"},
		// Neither the output nor an error: not observed, never safe.
		{ver, "show version\nJunos: 23.4", "show version\n", "", "ran", "not observed"},
		// `| count` is held to the lines the control's own run of the command
		// held: one line is an error's, that count is a run, any other count
		// is not observed, in either session (review R2).
		{count, "Count: 3 lines", "show interfaces ter | count\nCount: 1 lines", plain, "ran", "not run"},
		{count, "Count: 3 lines", "Count: 3 lines", plain, "ran", "ran"},
		{count, "Count: 3 lines", "Count: 2 lines", plain, "ran", "not observed"},
		{count, "Count: 5 lines", "Count: 1 lines", plain, "not observed", "not run"},
		{count, "Count: 3 lines", "Count: 3 lines", "show interfaces terse\nerror: something", "not observed", "not observed"},
		{count, "Count: 1 lines", "Count: 1 lines", plain, "not run", "not run"},
		{count, "Count: 3 lines", "show interfaces terse | count\n  ^\npermission denied.", plain, "ran", "refused"},
	} {
		cc, dc := abbrevCells(c.p, c.control, c.deny, c.plain)
		if cc != c.wantCtrl || dc != c.wantDeny {
			t.Errorf("%q: (%q, %q) = %q, %q; want %q, %q", c.p.cmd, oneLine(c.control), oneLine(c.deny), cc, dc,
				c.wantCtrl, c.wantDeny)
		}
	}
	if got := expansion("\a\a\ashow interfaces terse \nInterface"); got != "show interfaces terse" {
		t.Errorf("expansion trims the bell: %q", got)
	}
}

func TestSessionPermitted(t *testing.T) {
	permit := map[string]any{"event": "authorize_session", "verdict": "permit", "reason": "context_matched"}
	deny := map[string]any{"event": "authorize_session", "verdict": "deny", "reason": "no_rule_matched"}
	redeem := map[string]any{"event": "redeem", "reason": "token_redeemed"}
	for _, c := range []struct {
		recs []map[string]any
		want bool
	}{
		{[]map[string]any{redeem, permit}, true},
		{[]map[string]any{redeem, deny}, false},
		{[]map[string]any{redeem}, false},
		{nil, false},
	} {
		if got := sessionPermitted(c.recs); got != c.want {
			t.Errorf("sessionPermitted(%v) = %v, want %v", c.recs, got, c.want)
		}
	}
}

// noteBlocks reads a note's per-session output blocks: under each `### <name>`
// heading, "`<label>`:" followed by a fenced block, or one "Every RPC:" block,
// which the harness writes when no session opened and every RPC shares its reply.
func noteBlocks(t *testing.T, note string) map[string]map[string]string {
	t.Helper()
	heading := regexp.MustCompile(`(?m)^### (.+)$`)
	block := regexp.MustCompile("(?s)\n`([^`\n]+)`:\n\n```\n(.*?)\n```\n")
	every := regexp.MustCompile("(?s)\nEvery RPC:\n\n```\n(.*?)\n```\n")
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
		if m := every.FindStringSubmatch(note[l[1]:end]); m != nil {
			for _, r := range junosNetconfRPCs {
				out[name][r.rpc] = m[1]
			}
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
		cells := map[string][2]string{}
		for _, p := range junosAbbrevProbes {
			row := tableRow(note, tableCell(fmt.Sprintf("%q", p.cmd)))
			if row == nil {
				t.Errorf("%s: no row for %q", img, p.cmd)
				continue
			}
			cc, dc := abbrevCells(p, blocks["control"][p.cmd], blocks["deny"][p.cmd], blocks["control"][p.of])
			cells[p.cmd] = [2]string{cc, dc}
			if cc != row[1] || dc != baseCell(row[2]) {
				t.Errorf("%s %q: the note reads %q / %q, the classifier now %q / %q", img, p.cmd, row[1], row[2], cc, dc)
			}
		}
		// The read-off, derived again from the cells (review R3).
		enforced, expanded := abbrevVerdict(cells)
		if !strings.Contains(note, fmt.Sprintf("enforced: %v:", enforced)) ||
			!strings.Contains(note, fmt.Sprintf("JunosFacts.DenyMatchesExpanded (keywords) = %v:", expanded)) {
			t.Errorf("%s: the note's read-off is not what its cells now give: enforced %v, expanded %v", img, enforced, expanded)
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
		cells := make([][]string, len(junosNetconfVariants))
		for i, v := range junosNetconfVariants {
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
					// The committed notes printed an empty verdict (review R1);
					// context_matched is the permit's reason.
					permitted := strings.Contains(rest, "authorize_session permit") ||
						strings.Contains(rest, "authorize_session  context_matched")
					got = netconfDialCell(errors.New(errText), permitted,
						strings.Contains(rest, "paired control before") && strings.Contains(rest, "paired control after") &&
							!strings.Contains(rest, "no hello"))
				}
				cells[i] = append(cells[i], got)
				if got != want {
					t.Errorf("%s %s %s: the note reads %q, the classifier now %q", img, v.name, r.rpc, want, got)
				}
			}
		}
		// The read-off, derived again from the cells (review R3).
		if bound := netconfBound(cells); !strings.Contains(note, fmt.Sprintf("bind NETCONF RPCs: %v ", bound)) {
			t.Errorf("%s: the note's read-off is not what its cells now give: bound %v", img, bound)
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

// A collapsed "Every RPC:" block reads as the same reply under every RPC, so a
// note written either way gives the classifier the same cells.
func TestNoteBlocksReadsTheCollapsedEveryRPCForm(t *testing.T) {
	reply := "no session: alice04: the device sent no NETCONF hello: the NETCONF channel closed: EOF ()"
	collapsed := "### v\n\nEvery RPC:\n\n```\n" + reply + "\n```\n"
	var each strings.Builder
	each.WriteString("### v\n")
	for _, r := range junosNetconfRPCs {
		fmt.Fprintf(&each, "\n`%s`:\n\n```\n%s\n```\n", r.rpc, reply)
	}
	got, want := noteBlocks(t, collapsed), noteBlocks(t, each.String())
	if !reflect.DeepEqual(got, want) {
		t.Errorf("the collapsed form reads %v, the per-RPC form %v", got, want)
	}
	if len(got["v"]) != len(junosNetconfRPCs) {
		t.Errorf("the collapsed form fills %d RPCs, want %d", len(got["v"]), len(junosNetconfRPCs))
	}
}
