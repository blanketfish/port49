//go:build lab

package lab

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestL26cJunoscriptDeny measures the owner's SRX report
// (results/L26c-operator-juniper_srx.md, "Local class and `junoscript`") on
// the lab images: does `deny-commands "junoscript"` refuse `xml-mode netconf`
// from a CLI session, leave `show version` running, and close the NETCONF
// service on port 830 for that user?
//
// Four classes, each a token login under its own reply, over templates with
// the `view` bit:
//   - W, the wire deny: `deny-commands=junoscript` sent by TACACS+;
//   - L, the local deny: the same regex on the local template's class, no
//     deny sent;
//   - X, a wire deny naming `xml-mode` itself (an observation);
//   - C, the control: the same bits, no deny.
//
// R, the break-glass CLI, shows each entry form runs at all. The only RPC
// sent anywhere is `<get-software-information/>`.

var junosJSDClass = []string{
	"set system login class p49-jsd-view permissions view",
	"set system login user p49-jsd-view class p49-jsd-view",
	"set system login class p49-jsd-local permissions view",
	"set system login class p49-jsd-local deny-commands junoscript",
	"set system login user p49-jsd-local class p49-jsd-local",
}

var junosJSDDelete = []string{
	"delete system login user p49-jsd-view", "delete system login class p49-jsd-view",
	"delete system login user p49-jsd-local", "delete system login class p49-jsd-local",
}

// junosJSDVariant is a class and the entries typed in it: X types only the
// canonical one, since its question is whether a deny naming it binds.
type junosJSDVariant struct {
	junosVariant
	entries []string
}

// junosJSDEntries are the ways into NETCONF from the CLI: the canonical form,
// an abbreviation of `xml-mode`, `junoscript` (the name the owner saw the
// deny matched), and an abbreviation of it.
var junosJSDEntries = []string{"xml-mode netconf", "xml-mod netconf", "junoscript netconf", "junoscr netconf"}

var junosJSDVariants = []junosJSDVariant{
	{junosVariant{"W", `["local-user-name=p49-jsd-view", "deny-commands=junoscript"]`,
		"wire: view, and deny-commands junoscript sent by TACACS+"}, junosJSDEntries},
	{junosVariant{"L", `["local-user-name=p49-jsd-local"]`,
		"local: view, and deny-commands junoscript on the template's class, none sent"}, junosJSDEntries},
	{junosVariant{"X", `["local-user-name=p49-jsd-view", "deny-commands=xml-mode"]`,
		"wire: view, and a deny naming xml-mode itself"}, junosJSDEntries[:1]},
	{junosVariant{"C", `["local-user-name=p49-jsd-view"]`, "the control: view, no deny"}, junosJSDEntries},
}

// jsdEntry types entry at the CLI and, where a hello comes back, sends the
// client hello and `<get-software-information/>`. After a hello the session
// is NETCONF, and the caller closes it.
func jsdEntry(c *cliConn, entry string, r l26cRun) string {
	key := "entry: " + entry
	from := len(c.out.String())
	if err := c.send(entry); err != nil {
		r.cells[key] = "not observed"
		return r.cells[key]
	}
	out, err := c.expectFrom(from, junosPer, "</hello>", junosOpPrompt)
	if err == nil && !strings.Contains(out, "</hello>") {
		junosSettle(c)
		out = c.out.String()[from:]
	}
	r.outs[key] = out
	r.cells[key] = l26cEntryCell(out)
	if err != nil {
		r.cells[key] = "not observed"
	}
	if r.cells[key] != "hello" {
		return r.cells[key]
	}
	k := entry + ": get-software-information"
	if _, err := fmt.Fprint(c.in, junosL26cClientHello+"\n"); err != nil {
		r.cells[k] = "not observed"
		return r.cells[key]
	}
	from = len(c.out.String())
	if _, err := fmt.Fprint(c.in, "<rpc><get-software-information/></rpc>]]>]]>\n"); err != nil {
		r.cells[k] = "not observed"
		return r.cells[key]
	}
	reply, err := c.expectFrom(from, 60*time.Second, "</rpc-reply>")
	r.outs[k] = firstLines(reply, 12)
	r.cells[k] = l26cRPCCell(reply, "<software-information")
	if err != nil {
		r.cells[k] = "not observed"
	}
	return r.cells[key]
}

// jsdPort830 dials the NETCONF service with the next token and sends
// `<get-software-information/>` where a hello comes back. A channel the
// device closes after port49d permitted the session is "refused".
func (l *lab) jsdPort830(t *testing.T, r l26cRun) {
	t.Helper()
	off := l.mark()
	user, secret := l.nextLogin(t)
	n, hello, err := l.netconfDialPort(user, secret, "830")
	if err != nil {
		cell := "not observed"
		switch {
		case isAuthRejection(err):
			cell = "login refused"
		case sessionPermitted(l.drainRecords(off, 10*time.Second)) &&
			(strings.Contains(err.Error(), "the NETCONF channel closed:") ||
				strings.Contains(err.Error(), "subsystem request failed")):
			cell = "refused"
		}
		r.cells["port 830"] = cell
		r.outs["port 830"] = oneLine(err.Error())
		return
	}
	defer n.Close()
	r.cells["port 830"] = "hello"
	r.outs["port 830"] = firstLines(hello, 5)
	reply, err := n.rpc(1, "<get-software-information/>")
	r.outs["port 830: get-software-information"] = firstLines(reply, 10)
	r.cells["port 830: get-software-information"] = l26cRPCCell(reply, "<software-information")
	if err != nil {
		r.cells["port 830: get-software-information"] = "not observed"
	}
}

// junosJSDCanonical are the probes points 1-3 rest on: a W or L refusal of
// one must be isolated by C reaching it.
var junosJSDCanonical = []string{"entry: xml-mode netconf", "entry: junoscript netconf", "port 830"}

// jsdVerdict reads each W and L cell against C: a refusal is "deny" only
// where C, with the same bits and no deny, reached the probe; otherwise it is
// "unisolated", since the refusal may be the bits' or the form's. A cell that
// ran or reached NETCONF is "reached". unisolated lists every canonical cell
// that is not isolated, and any is a failure.
func jsdVerdict(runs map[string]l26cRun, probes []string) (readings map[string]string, unisolated []string) {
	readings = map[string]string{}
	for _, cls := range []string{"W", "L"} {
		for _, p := range probes {
			cell, ok := runs[cls].cells[p]
			if !ok {
				continue
			}
			reached := func(c string) bool { return l26cReached(c) || c == "ran" }
			var v string
			switch {
			case reached(cell):
				v = "reached"
			case (cell == "refused" || cell == "login refused") && reached(runs["C"].cells[p]):
				v = "deny"
			default:
				v = "unisolated"
			}
			readings[cls+" "+p] = v
			if v == "unisolated" && slices.Contains(junosJSDCanonical, p) {
				unisolated = append(unisolated, fmt.Sprintf("%s %s: %s, and C %s", cls, p, cell, cellOr(runs["C"], p)))
			}
		}
	}
	return readings, unisolated
}

// jsdTokensLeft is how many seeded logins this platform's run has left.
func (l *lab) jsdTokensLeft() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return tokenPoolSize - l.tokenN
}

// jsdAccounting is the `cmd=` AV pair of every accounting record since off,
// one per line: what the device reported the operator typed.
func (l *lab) jsdAccounting(off int64) string {
	var b strings.Builder
	for _, rec := range l.drainRecords(off, 8*time.Second) {
		if str(rec, "event") != "account" {
			continue
		}
		for _, a := range strs(sub(rec, "record"), "raw") {
			if strings.HasPrefix(a, "cmd=") {
				fmt.Fprintf(&b, "%s %s\n", str(sub(rec, "session"), "username"), a)
			}
		}
	}
	return b.String()
}

func TestL26cJunoscriptDeny(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		stop := l.capture(t, "L26c-junoscript")
		defer stop()
		commit := l.junosConfigureAdmin(t, junosJSDClass)
		defer l.junosConfigureAdmin(t, junosJSDDelete)
		defer func() {
			if std, err := l.configPath(); err == nil {
				if err := l.restart(std); err != nil {
					t.Errorf("could not put port49d back on the lab config: %v", err)
				}
			}
		}()
		runs := map[string]l26cRun{"R": newL26cRun()}
		acct := map[string]string{}

		// R: what completion offers, and each entry over break-glass, one
		// session each since a hello ends the CLI.
		var forms []string
		var classCfg string
		breakglass := func(fn func(c *cliConn)) {
			c, err := l.junosCLI(breakglassUser, breakglassPassword)
			if err != nil {
				t.Fatalf("no break-glass CLI: %v", err)
			}
			defer c.Close()
			fn(c)
		}
		breakglass(func(c *cliConn) {
			w := &keywordWalk{c: c, logf: t.Logf, prompt: "@" + junosHost + "> "}
			for _, p := range []string{"xml-mode", "junoscript"} {
				words, ph, err := w.completion(p)
				forms = append(forms, fmt.Sprintf("`%s ?`: %v, placeholder %v, err %v", p, words, ph, err))
			}
			junosSettle(c)
			out, _ := c.sendExpect("show configuration system login | display set | match p49-jsd", junosPer, junosOpPrompt)
			classCfg = out
			junosSettle(c)
			o, err := l26cSend(c, "show version")
			runs["R"].outs["show version"] = firstLines(o, 6)
			runs["R"].cells["show version"] = l26cCLICell(o, "Junos:")
			if err != nil {
				runs["R"].cells["show version"] = "not observed"
			}
		})
		for _, e := range junosJSDEntries {
			breakglass(func(c *cliConn) { jsdEntry(c, e, runs["R"]) })
		}

		for _, v := range junosJSDVariants {
			r := newL26cRun()
			runs[v.name] = r
			off := l.mark()
			var c *cliConn
			open := func(label string) bool {
				if l.jsdTokensLeft() < 2 { // keep one for port 830
					r.outs["pool"] += "the seeded login pool ran out before " + label + "\n"
					return false
				}
				cc, run, _ := l.junosLogin(t, v.name+" "+label, v.attrs)
				if cc == nil {
					t.Fatalf("%s: the session did not open, so nothing was measured: %s", v.name, run.loginErr)
				}
				if _, ok := r.outs["show cli authorization"]; !ok {
					r.outs["show cli authorization"] = run.auth
				}
				c = cc
				return true
			}
			if !open("show version") {
				continue
			}
			o, err := l26cSend(c, "show version")
			r.outs["show version"] = firstLines(o, 6)
			r.cells["show version"] = l26cCLICell(o, "Junos:")
			if err != nil {
				r.cells["show version"] = "not observed"
			}
			for _, e := range v.entries {
				if c == nil && !open(e) {
					r.cells["entry: "+e] = "not run (token pool)"
					continue
				}
				if jsdEntry(c, e, r) == "hello" {
					c.Close()
					c = nil
				}
			}
			if c != nil {
				c.Close()
			}

			// Port 830, under the same reply.
			cfg, err := l.derivedConfigCmd("junos-jsd-"+l16Slug(v.name), v.attrs, "", "")
			if err == nil {
				err = l.restart(cfg)
			}
			if err != nil {
				t.Fatalf("%s: port49d with %s: %v", v.name, v.attrs, err)
			}
			l.jsdPort830(t, r)
			acct[v.name] = l.jsdAccounting(off)
		}

		probes := []string{"show version"}
		for _, e := range junosJSDEntries {
			probes = append(probes, "entry: "+e, e+": get-software-information")
		}
		probes = append(probes, "port 830", "port 830: get-software-information")
		for _, name := range []string{"W", "L", "X", "C", "R"} {
			for _, p := range probes {
				if runs[name].cells[p] == "not observed" {
					t.Errorf("not observed: %s in %s", p, name)
				}
			}
		}
		readings, unisolated := jsdVerdict(runs, probes)
		for _, u := range unisolated {
			t.Errorf("unisolated: %s", u)
		}

		var b strings.Builder
		fmt.Fprintf(&b, "The classes were committed: %s.\n\n```\n%s\n```\n\nOn the device afterwards:\n\n```\n%s\n```\n\n",
			commitWord(commit), strings.Join(junosJSDClass, "\n"), strings.TrimSpace(classCfg))
		b.WriteString("| class | reply | why |\n|---|---|---|\n")
		for _, v := range junosJSDVariants {
			fmt.Fprintf(&b, "| %s | `%s` | %s |\n", v.name, tableCell(v.attrs), v.why)
		}
		b.WriteString("| R | break-glass, local | every permission: shows each entry form runs at all |\n\n")
		fmt.Fprintf(&b, "Completion over break-glass: %s.\n\n", strings.Join(forms, "; "))
		b.WriteString("Only `<get-software-information/>` was sent in any NETCONF session. A cell is `hello` " +
			"(a NETCONF hello came back), `refused` (the CLI's refusal words, or the channel closed after " +
			"port49d permitted the session), `result` (the RPC's `<software-information>`), `—` (not typed: " +
			"the class does not type it, or its entry was refused).\n\n")
		b.WriteString("| probe | W | L | X | C | R |\n|---|---|---|---|---|---|\n")
		for _, p := range probes {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s |\n", tableCell(p), cellOr(runs["W"], p), cellOr(runs["L"], p),
				cellOr(runs["X"], p), cellOr(runs["C"], p), cellOr(runs["R"], p))
		}
		b.WriteString("\n### Isolation\n\nA W or L refusal is `deny` only where C, with the same bits and no deny, " +
			"reached the probe; otherwise `unisolated`, and it says nothing about the deny. A canonical probe " +
			"(`" + strings.Join(junosJSDCanonical, "`, `") + "`) left unisolated fails the test.\n\n")
		b.WriteString("| probe | W | L |\n|---|---|---|\n")
		for _, p := range probes {
			w, l := readings["W "+p], readings["L "+p]
			if w == "" && l == "" {
				continue
			}
			fmt.Fprintf(&b, "| %s | %s | %s |\n", tableCell(p), jsdOrDash(w), jsdOrDash(l))
		}
		b.WriteString("\n### Accounting `cmd=` by time window (a class's block can open with late records of the one before)\n")
		for _, v := range junosJSDVariants {
			fmt.Fprintf(&b, "\n%s:\n\n```\n%s```\n", v.name, jsdOrNone(acct[v.name]))
		}
		for _, name := range []string{"W", "L", "X", "C", "R"} {
			fmt.Fprintf(&b, "\n### %s\n", name)
			keys := make([]string, 0, len(runs[name].outs))
			for k := range runs[name].outs {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				fmt.Fprintf(&b, "\n`%s`:\n\n```\n%s\n```\n", k, firstLines(runs[name].outs[k], 20))
			}
		}
		l.result(t, "L26c-junoscript", "Whether `deny-commands \"junoscript\"`, sent by TACACS+ or set on the local "+
			"class, refuses `xml-mode netconf` from a CLI session while `show version` still runs, and closes the "+
			"NETCONF service on port 830 for that user; with a control of the same bits and no deny. Also: whether a "+
			"deny naming `xml-mode` binds, and whether abbreviations of `xml-mode` and `junoscript` are refused "+
			"under the `junoscript` deny (the owner's SRX report, results/L26c-operator-juniper_srx.md).",
			b.String())
	})
}

func jsdOrDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func jsdOrNone(s string) string {
	if s == "" {
		return "(none)\n"
	}
	return s
}
