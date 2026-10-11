//go:build lab

package lab

import (
	"fmt"
	"strings"
	"testing"
)

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

// The `save` cells run under p49-l58-save (`permissions all`): the first run
// (2026-10-11) showed a `view` class cannot run `save` at all on either image
// (syntax error at the subcommand, then permission denied), so its control
// never reached and `save` read unproven whatever the deny did. Whether `save`
// is a keyword to deny-commands does not depend on the class; the entries keep
// the readonly's `view` class.
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
			return "proven", cmd + "; the control's CLI took `save` and stopped after it"
		}
	}
	return "unproven", ""
}

// l58PastSave reports whether the control's CLI took `save` and stopped
// later: a platform refusal of the whole command, or a caret past `save`.
func l58PastSave(out string, promptLen int) bool {
	if strings.Contains(strings.ToLower(out), "command is not valid on the") {
		return true
	}
	at := caretAt(out, promptLen)
	return at != "" && !caretOn(at, "save") && !strings.HasPrefix(at, "save")
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
		cmds := append([]string{"show version | count"}, junosL58Saves...)

		cells := map[string]map[string]string{"control": {}, "deny": {}}
		outs := map[string]map[string]string{}
		for _, s := range []struct{ name, attrs string }{{"control", saveControl}, {"deny", saveDeny}} {
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
			for _, s := range []struct{ name, attrs string }{{"control", control}, {"deny", deny}} {
				cell, out := l.l58Entry(t, s.name+" "+e, s.attrs, e)
				cells[s.name][e], entryOuts[s.name+" "+e] = cell, out
			}
			if cells["control"][e] != "greeting" {
				t.Fatalf("INVALID: the control's `%s` %s, so the deny's answer is not isolated", e, cells["control"][e])
			}
		}

		var b strings.Builder
		fmt.Fprintf(&b, "The class was committed: %s.\n\n```\n%s\n```\n\n", commitWord(commit), strings.Join(junosL58Class, "\n"))
		fmt.Fprintf(&b, "Completion over break-glass: `save ?`: %s; `xml-mode ?`: %s.\n\n", listings["save"], listings["xml-mode"])
		fmt.Fprintf(&b, "| session | reply |\n|---|---|\n| control (`save`) | `%s` |\n| deny (`save`) | `%s` |\n"+
			"| control (entries) | `%s` |\n| deny (entries) | `%s` |\n\n",
			tableCell(saveControl), tableCell(saveDeny), tableCell(control), tableCell(deny))
		b.WriteString("| probe | control | deny |\n|---|---|---|\n")
		for _, p := range append(cmds, junosL58Entries...) {
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", tableCell(p), cells["control"][p], cells["deny"][p])
		}
		fmt.Fprintf(&b, "\n### Gates\n\n- **G3** `save`: **%s**", save)
		if by != "" {
			fmt.Fprintf(&b, " (by `%s`)", tableCell(by))
		}
		closed := cells["deny"]["xml-mode"] == "refused" && cells["deny"]["xml-mode netconf need-trailer"] == "refused"
		fmt.Fprintf(&b, ".\n- **G4** `xml-mode` under the `junoscript` deny: bare %s, `netconf` %s: **%s**.\n",
			cells["deny"]["xml-mode"], cells["deny"]["xml-mode netconf need-trailer"],
			map[bool]string{true: "closed", false: "not closed"}[closed])
		b.WriteString("\n### Outputs\n")
		for _, s := range []string{"control", "deny"} {
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
