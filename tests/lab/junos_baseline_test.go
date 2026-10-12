//go:build lab

package lab

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/policy"
)

// l58ShippedReadonlyDeny is the deny-commands set 1.2.0 sends this lab node
// for a readonly granted `show **` less `show configuration **`: the
// baseline's `word **` denies as one alternative nested inside `^( … )$`
// beside the grant's deny (decision 44 ruling 10). L58's own deny is that
// alternative alone; this is the form a device meets. A rendered value that
// is not nested is INVALID: the session would measure the L58 form again.
func (l *lab) l58ShippedReadonlyDeny(t *testing.T) string {
	t.Helper()
	inv, err := admission.LoadFile(filepath.Join(root, "tests", "lab", "inventory-lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	body := "platform_set: 1.2.0\nscopes:\n  - {name: all_devices, match: {}}\nroles:\n" +
		"  - {name: r, privilege: readonly, permit: [\"show **\"], deny: [\"show configuration **\"]}\n" +
		"subjects:\n  - {name: slice_operator, identity: [\"" + slicePrincipal + "\"], username: " + sliceUser +
		", enable: none, token_ttl: 60s}\ngrants:\n  - {subject: slice_operator, scope: all_devices, roles: [r]}\n"
	path := filepath.Join(t.TempDir(), "l58-shipped.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(path, policy.Env{Devices: inv.Devices})
	if err != nil {
		t.Fatalf("INVALID: the shipped readonly's policy does not load: %v", err)
	}
	device, _ := pol.Device(l.p.node)
	res, err := pol.ResolveSubject("slice_operator", device, time.Now())
	if err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	for _, a := range res.Blob.Attributes {
		if v, ok := strings.CutPrefix(a, "deny-commands="); ok {
			if !strings.HasPrefix(v, "^(") || !strings.HasSuffix(v, ")$") || !strings.Contains(v, " *(") ||
				!strings.Contains(v, "save") || !strings.Contains(v, "junoscript") {
				t.Fatalf("INVALID: set 1.2.0's readonly deny is not the nested form: %s", v)
			}
			return v
		}
	}
	t.Fatalf("INVALID: set 1.2.0's readonly reply carries no deny-commands: %q", res.Blob.Attributes)
	return ""
}

// TestL58JunosBaselineWords measures the two baseline words set 1.2.0's
// readonly reply rests on (spec §15 L58; decision 44 ruling 10). `save`: L26b
// proved it a keyword on vJunos-router and left it unproven on vSRX, whose
// control took the hidden `save dhcp-security-snoop` and refused the file
// name after it; each candidate below is typed in both sessions, and the word
// is proven where the control ran one with `| count`'s evidence and the deny
// refused that one, its caret under `save` (l26bVerdict). `xml-mode`: L26c
// measured `xml-mode netconf` refused under a deny of `junoscript`; bare
// `xml-mode`, the Junos XML protocol, was not typed. Both are typed under the
// factored alternative set 1.2.0 renders, ` *(save|junoscript)( .*)? *(\|.*)?`,
// against a control with the same class and no deny.
//
// Positive controls are enforced: a session that does not open, `show
// version` not running in either CLI session, or the control not reaching
// the XML greeting for either entry is INVALID, before any note is written.
// `save` unproven, or an entry reached under the deny, is a result: the note
// records it and Task 3's gates stop the plan.

// The `save` cells run under p49-l58-save (`permissions all`), so the control
// can reach `save` and the deny is the only difference between the two
// sessions; the entries keep the readonly's `view` class. The same save
// candidates are also typed once in a `view` session with no deny, recorded as
// "control (view)": information only, never a gate and never INVALID.
var junosL58Class = []string{
	"set system login class p49-l58-view permissions view",
	"set system login user p49-l58-view class p49-l58-view",
	"set system login class p49-l58-save permissions all",
	"set system login user p49-l58-save class p49-l58-save",
}

var junosL58Delete = []string{"delete system login user p49-l58-view", "delete system login class p49-l58-view",
	"delete system login user p49-l58-save", "delete system login class p49-l58-save"}

// junosL58Deny is the factored alternative naming both words, as set 1.2.0
// renders a reply's `word **` denies.
const junosL58Deny = `^ *(save|junoscript)( .*)? *(\|.*)?$`

// junosL58Saves are the `save` commands typed: vJunos-router's L26b probe,
// and the hidden command vSRX took, without the file name it refused.
var junosL58Saves = []string{
	"save dhcp-security-snoop /var/tmp/p49-l58.snoop | count",
	"save dhcp-security-snoop | count",
}

// junosL58Entries are the commands that turn a CLI session into an XML
// session: bare `xml-mode` greets with `<junoscript`, `xml-mode netconf` with
// a NETCONF `<hello>`.
var junosL58Entries = []string{"xml-mode", "xml-mode netconf need-trailer"}

// l58EntryCell is a CLI's answer to an entry: greeting (`<junoscript` or a
// NETCONF hello, and no refusal), refused, or not observed.
func l58EntryCell(out string) string {
	greeted := strings.Contains(out, "<junoscript") || strings.Contains(out, "</hello>")
	refused := containsAny(strings.ToLower(out), junosL26cRefusal)
	switch {
	case greeted && !refused:
		return "greeting"
	case refused && !greeted:
		return "refused"
	}
	return "not observed"
}

// l58Save is `save`'s verdict on one image from each candidate's control
// and deny cells: proven where some candidate is (l26bVerdict, offered:
// `save` is never absent here, since the image took it in L26b), and the
// candidate that proved it. vSRX has no `save` subcommand a session can run
// to the end (21.4 says "command is not valid on the vsrx", or a syntax error
// past it), so a candidate also proves the word where the control's CLI took
// `save` and stopped later, and the deny refused it with its caret under
// `save` (l26bDenyCell): the deny's refusal is then the word's alone.
func l58Save(control, deny map[string]string, controlOuts map[string]string, promptLen int) (string, string) {
	for _, cmd := range junosL58Saves {
		if l26bVerdict(control[cmd], deny[cmd], true, controlOuts[cmd]) == "proven" {
			return "proven", cmd
		}
	}
	for _, cmd := range junosL58Saves {
		if deny[cmd] == "refused" && l58PastSave(controlOuts[cmd], promptLen) {
			return "proven", cmd + "; the control's CLI took save and stopped after it"
		}
	}
	return "unproven", ""
}

// l58PastSave reports whether the control's CLI took `save` and stopped
// later: a platform refusal of the whole command, or a caret past `save`.
// out is one command's window (junosProbe: from the command's send, trimmed
// after its echo, settled before the next command), so the platform-refusal
// text cannot be an earlier command's spill.
func l58PastSave(out string, promptLen int) bool {
	if strings.Contains(strings.ToLower(out), "command is not valid on the") {
		return true
	}
	at := caretAt(out, promptLen)
	return at != "" && !caretOn(at, "save") && !strings.HasPrefix(at, "save")
}

// l58Nested is G5: the shipped readonly's nested deny is enforced as the
// factored form where both XML entries read refused, and every `save`
// candidate the factored deny refused is refused by the shipped form too with
// the caret under `save`, as G3 reads it: on vSRX the control cannot run `save`,
// so a refusal anywhere else could be the image's own. shippedOuts are the
// shipped session's windows; promptLen is its prompt's length.
func l58Nested(deny, shipped, shippedOuts map[string]string, promptLen int) bool {
	for _, e := range junosL58Entries {
		if shipped[e] != "refused" {
			return false
		}
	}
	for _, cmd := range junosL58Saves {
		if deny[cmd] == "refused" && (shipped[cmd] != "refused" ||
			!caretOn(caretAt(shippedOuts[cmd], promptLen), "save")) {
			return false
		}
	}
	return true
}

// l58ViewControl types the save candidates in a session under attrs (a `view`
// class, no deny) and reads each cell. It is information for the note: a
// session or a command that is not observed reads "not observed", and nothing
// here fails the test or gates a result.
func (l *lab) l58ViewControl(t *testing.T, attrs string) (cells, outs map[string]string) {
	t.Helper()
	cells, outs = map[string]string{}, map[string]string{}
	c, r, _ := l.junosLogin(t, "control (view)", attrs)
	if c == nil {
		for _, cmd := range junosL58Saves {
			cells[cmd], outs[cmd] = "not observed", "(no session: "+r.loginErr+")"
		}
		return cells, outs
	}
	defer c.Close()
	for _, cmd := range junosL58Saves {
		out, err := l.junosProbe(c, junosProbe{cmd: cmd})
		outs[cmd] = out
		cells[cmd] = l26bCell(out, nil)
		if err != nil {
			cells[cmd] = "not observed"
			break // the session's state is unknown past a missed prompt
		}
	}
	for _, cmd := range junosL58Saves {
		if _, ok := cells[cmd]; !ok {
			cells[cmd], outs[cmd] = "not observed", ""
		}
	}
	return cells, outs
}

// l58Entry types entry in a fresh session under attrs and reads the greeting
// or the refusal; the session is XML afterwards, so it is closed.
func (l *lab) l58Entry(t *testing.T, name, attrs, entry string) (string, string) {
	t.Helper()
	c, r, _ := l.junosLogin(t, name, attrs)
	if c == nil {
		t.Fatalf("INVALID: %s: the session did not open: %s", name, r.loginErr)
	}
	defer c.Close()
	from := len(c.out.String())
	if err := c.send(entry); err != nil {
		return "not observed", err.Error()
	}
	out, err := c.expectFrom(from, junosPer, "<junoscript", "</hello>", junosOpPrompt)
	if err == nil && !strings.Contains(out, "<junoscript") && !strings.Contains(out, "</hello>") {
		junosSettle(c)
		out = c.out.String()[from:]
	}
	if err != nil {
		return "not observed", out
	}
	return l58EntryCell(out), out
}

func TestL58JunosBaselineWords(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		stop := l.capture(t, "L58")
		defer stop()

		// The completions after each word, over break-glass, before any token.
		listings := map[string]string{}
		func() {
			c, err := l.junosCLI(breakglassUser, breakglassPassword)
			if err != nil {
				t.Fatalf("INVALID: no break-glass CLI: %v", err)
			}
			defer c.Close()
			if err := junosPrepare(c); err != nil {
				t.Fatalf("INVALID: set cli screen-length 0 not observed within %s: %v", junosPer, err)
			}
			w := &keywordWalk{c: c, logf: t.Logf, prompt: "@" + junosHost + "> "}
			for _, p := range []string{"save", "xml-mode"} {
				words, ph, err := w.completion(p)
				listings[p] = fmt.Sprintf("%s (placeholder %v, err %v)", strings.Join(words, " "), ph, err)
			}
		}()

		commit := l.junosConfigureAdmin(t, junosL58Class)
		defer l.junosConfigureAdmin(t, junosL58Delete)
		defer func() {
			if std, err := l.configPath(); err == nil {
				if err := l.restart(std); err != nil {
					t.Errorf("could not put port49d back on the lab config: %v", err)
				}
			}
		}()

		const class, saveClass = `"local-user-name=p49-l58-view"`, `"local-user-name=p49-l58-save"`
		quote := func(re string) string { return strings.ReplaceAll(re, `\`, `\\`) }
		control := "[" + class + "]"
		deny := "[" + class + `, "deny-commands=` + quote(junosL58Deny) + `"]`
		saveControl := "[" + saveClass + "]"
		saveDeny := "[" + saveClass + `, "deny-commands=` + quote(junosL58Deny) + `"]`
		shipped := l.l58ShippedReadonlyDeny(t)
		saveShipped := "[" + saveClass + `, "deny-commands=` + quote(shipped) + `"]`
		entryShipped := "[" + class + `, "deny-commands=` + quote(shipped) + `"]`
		cmds := append([]string{"show version | count"}, junosL58Saves...)

		cells := map[string]map[string]string{"control": {}, "deny": {}, "shipped": {}}
		outs := map[string]map[string]string{}
		for _, s := range []struct{ name, attrs string }{{"control", saveControl}, {"deny", saveDeny}, {"shipped", saveShipped}} {
			o, _, auth := l.l26bSession(t, s.name, s.attrs, cmds, false)
			// l26bSession says why with t.Errorf; nothing is written after it.
			if t.Failed() {
				t.Fatalf("INVALID: %s: the session did not open, or a command was not observed within %s", s.name, junosPer)
			}
			outs[s.name] = o
			outs[s.name]["auth"] = auth
			promptLen := len(o[l26bUserKey] + "@" + junosHost + "> ")
			cells[s.name]["show version | count"] = l26bCell(o["show version | count"], nil)
			for _, cmd := range junosL58Saves {
				if s.name == "control" {
					cells[s.name][cmd] = l26bCell(o[cmd], nil)
				} else {
					cells[s.name][cmd] = l26bDenyCell(o[cmd], "save", nil, promptLen)
				}
			}
			if cells[s.name]["show version | count"] != "ran" {
				t.Fatalf("INVALID: %s: `show version | count` %s, so the session measures nothing",
					s.name, cells[s.name]["show version | count"])
			}
		}
		save, by := l58Save(cells["control"], cells["deny"], outs["control"],
			len(outs["control"][l26bUserKey]+"@"+junosHost+"> "))

		entryOuts := map[string]string{}
		for _, e := range junosL58Entries {
			for _, s := range []struct{ name, attrs string }{{"control", control}, {"deny", deny}, {"shipped", entryShipped}} {
				cell, out := l.l58Entry(t, s.name+" "+e, s.attrs, e)
				cells[s.name][e], entryOuts[s.name+" "+e] = cell, out
			}
			if cells["control"][e] != "greeting" {
				t.Fatalf("INVALID: the control's `%s` %s, so the deny's answer is not isolated", e, cells["control"][e])
			}
		}

		// Information only: the save candidates in a view session, no deny.
		viewCells, viewOuts := l.l58ViewControl(t, control)

		var b strings.Builder
		fmt.Fprintf(&b, "The class was committed: %s.\n\n```\n%s\n```\n\n", commitWord(commit), strings.Join(junosL58Class, "\n"))
		fmt.Fprintf(&b, "Completion over break-glass: `save ?`: %s; `xml-mode ?`: %s.\n\n", listings["save"], listings["xml-mode"])
		fmt.Fprintf(&b, "| session | reply |\n|---|---|\n| control (`save`) | `%s` |\n| deny (`save`) | `%s` |\n"+
			"| shipped readonly (`save`) | `%s` |\n| control (entries) | `%s` |\n| deny (entries) | `%s` |\n"+
			"| shipped readonly (entries) | `%s` |\n\n",
			tableCell(saveControl), tableCell(saveDeny), tableCell(saveShipped), tableCell(control), tableCell(deny),
			tableCell(entryShipped))
		b.WriteString("| probe | control | deny | shipped readonly |\n|---|---|---|---|\n")
		for _, p := range append(cmds, junosL58Entries...) {
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", tableCell(p), cells["control"][p], cells["deny"][p], cells["shipped"][p])
		}
		fmt.Fprintf(&b, "\n### Gates\n\n- **G3** `save`: **%s**", save)
		if by != "" {
			fmt.Fprintf(&b, " (by `%s`)", tableCell(by))
		}
		closed := cells["deny"]["xml-mode"] == "refused" && cells["deny"]["xml-mode netconf need-trailer"] == "refused"
		fmt.Fprintf(&b, ".\n- **G4** `xml-mode` under the `junoscript` deny: bare %s, `netconf` %s: **%s**.\n",
			cells["deny"]["xml-mode"], cells["deny"]["xml-mode netconf need-trailer"],
			map[bool]string{true: "closed", false: "not closed"}[closed])
		nested := l58Nested(cells["deny"], cells["shipped"], outs["shipped"],
			len(outs["shipped"][l26bUserKey]+"@"+junosHost+"> "))
		// A measurement, not an assertion: Step 4 reads this line and stops the plan on "NOT enforced".
		fmt.Fprintf(&b, "- G5: the shipped readonly form (`%s`): **%s**.\n", tableCell(shipped),
			map[bool]string{true: "enforced as the factored form", false: "NOT enforced as the factored form"}[nested])
		fmt.Fprintf(&b, "\n### Control (view), information only\n\nThe save candidates typed in a session under `%s` "+
			"(class p49-l58-view, no deny). Never a gate.\n\n| probe | control (view) |\n|---|---|\n", tableCell(control))
		for _, p := range junosL58Saves {
			fmt.Fprintf(&b, "| `%s` | %s |\n", tableCell(p), viewCells[p])
		}
		for _, p := range junosL58Saves {
			fmt.Fprintf(&b, "\n`%s` (control (view)):\n\n```\n%s\n```\n", tableCell(p), viewOuts[p])
		}
		b.WriteString("\n### Outputs\n")
		for _, s := range []string{"control", "deny", "shipped"} {
			fmt.Fprintf(&b, "\n#### %s, user `%s`\n\n```\n%s\n```\n", s, outs[s][l26bUserKey], outs[s]["auth"])
			for _, p := range cmds {
				fmt.Fprintf(&b, "\n`%s`:\n\n```\n%s\n```\n", tableCell(p), outs[s][p])
			}
			for _, e := range junosL58Entries {
				fmt.Fprintf(&b, "\n`%s`:\n\n```\n%s\n```\n", e, entryOuts[s+" "+e])
			}
		}
		l.entryResult(t, "L58", "Whether `save` is a keyword to deny-commands, and whether bare `xml-mode` and `xml-mode "+
			"netconf` are refused, under set 1.2.0's factored deny naming `save` and `junoscript`, each against a "+
			"control with the same class and no deny (spec §15 L58; decision 44 ruling 10).", b.String())
	})
}
