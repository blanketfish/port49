//go:build lab

package lab

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestL26cJunosRPCReach asks whether a projected Junos CLI session can reach
// an RPC past its denies (the controller's L26c brief; Task 13a review I1;
// gates Task 14's branch M). Task 3b measured that wire denies do not bind
// NETCONF RPCs (L12-netconf-juniper_*.md), so branch M turns every management
// service off but ssh and telnet. That protects the device only if a CLI
// session cannot reach an RPC itself: through the hidden `xml-mode netconf
// need-trailer`, through the NETCONF subsystem on port 22 with `netconf ssh`
// deleted, through `op url`, or through `start shell`.
//
// Three classes, each a token login under its own reply, over one template
// with the measured readonly bits (`view`):
//   - P, projected: a deny naming `show configuration`, as Task 7 renders it;
//   - F, the fail-closed reply: `deny-commands ^.*$`;
//   - C, the control: the same template, no deny.
//
// C isolates both P and F, since all three hold the same bits. R, the
// break-glass CLI (every permission, local), shows that each probe runs at
// all, so a refusal in C too is the bits', not a probe that cannot run.
//
// Evidence is positive only:
//   - a NETCONF hello (`<hello … </hello>`);
//   - an RPC result (`<software-information`, or the host name the
//     configuration holds);
//   - `op url` accepted up to the point it would open the file (an error
//     naming the file);
//   - a shell prompt (`%` or `$`), from which only `exit` is typed.
//
// A refusal is the CLI's refusal words, or an `<rpc-error>` of severity error.
// Anything else is not observed, and fails. Every read has junosPer, and each
// RPC 60 s.

var junosL26cClass = []string{
	"set system login class p49-l26c-view permissions view",
	"set system login user p49-l26c-view class p49-l26c-view",
}

var junosL26cDelete = []string{"delete system login user p49-l26c-view", "delete system login class p49-l26c-view"}

var junosL26cVariants = []junosVariant{
	{"P", `["local-user-name=p49-l26c-view", "deny-commands=^ *show +configuration( .*)? *(\\|.*)?$"]`,
		"projected: view, and a deny naming show configuration"},
	{"F", `["local-user-name=p49-l26c-view", "deny-commands=^.*$"]`, "the fail-closed reply over the same template"},
	{"C", `["local-user-name=p49-l26c-view"]`, "the control: view, no deny"},
}

// junosL26cXMLMode is the canonical hidden command that turns a CLI session
// into a NETCONF session.
const junosL26cXMLMode = "xml-mode netconf need-trailer"

// junosL26cRPCs are sent in every NETCONF session reached, each with its
// evidence.
var junosL26cRPCs = []struct{ name, body, evidence string }{
	{"get-software-information", "<rpc><get-software-information/></rpc>", "<software-information"},
	{"get-configuration", "<rpc><get-configuration/></rpc>", "host-name"},
	{"command show configuration", "<rpc><command>show configuration</command></rpc>", "host-name"},
}

const junosL26cClientHello = `<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities>` +
	`<capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>]]>]]>`

var junosL26cRefusal = []string{"permission denied", "unknown command", "syntax error", "not allowed", "missing argument"}

// junosL26cOpenErr is `op url` having gone as far as opening the local file:
// an error about the file, not a refusal of the command.
var junosL26cOpenErr = regexp.MustCompile(`(?i)(no such file|not found|does not exist|could not|failed to|unable to)`)

// l26cEntryCell is a CLI's answer to a command that turns the session into
// NETCONF: hello, refused, or not observed.
func l26cEntryCell(out string) string {
	hello := strings.Contains(out, "<hello") && strings.Contains(out, "</hello>")
	refused := containsAny(strings.ToLower(out), junosL26cRefusal)
	switch {
	case hello && !refused:
		return "hello"
	case refused && !hello:
		return "refused"
	}
	return "not observed"
}

// l26cRPCCell is an RPC reply's outcome: result (its evidence), refused (an
// `<rpc-error>` of severity error and no evidence), or not observed.
func l26cRPCCell(reply, evidence string) string {
	switch {
	case strings.Contains(reply, evidence):
		return "result"
	case strings.Contains(reply, "<rpc-error>") && netconfSeverityError.MatchString(reply):
		return "refused"
	}
	return "not observed"
}

// l26cOpURLCell is `op url` to a local file that does not exist: accepted
// (an error about the file, so the CLI took the command to where it would
// fetch), refused (the CLI's refusal), or not observed.
func l26cOpURLCell(out string) string {
	refused := containsAny(strings.ToLower(out), junosL26cRefusal)
	switch {
	case refused:
		return "refused"
	case junosL26cOpenErr.MatchString(out):
		return "accepted"
	}
	return "not observed"
}

// l26cShellCell is `start shell`: shell (a `%` or `$` prompt last), refused,
// or not observed.
func l26cShellCell(out string) string {
	last := strings.TrimRight(out, " \r\n")
	switch {
	case strings.HasSuffix(last, "%") || strings.HasSuffix(last, "$"):
		return "shell"
	case containsAny(strings.ToLower(out), junosL26cRefusal):
		return "refused"
	}
	return "not observed"
}

// l26cCLICell is a plain command's outcome: ran (its evidence), refused, or
// not observed.
func l26cCLICell(out, evidence string) string {
	refused := containsAny(strings.ToLower(out), junosL26cRefusal)
	switch {
	case strings.Contains(out, evidence) && !refused:
		return "ran"
	case refused && !strings.Contains(out, evidence):
		return "refused"
	}
	return "not observed"
}

// l26cSend types cmd and reads its window drained to quiet (review L26b
// I-2), so a refusal the CLI prints after its first prompt stays in its own
// command's window.
func l26cSend(c *cliConn, cmd string) (string, error) {
	from := len(c.out.String())
	_, err := c.sendExpect(cmd, junosPer, junosOpPrompt)
	if err == nil {
		err = junosSettle(c)
	}
	return c.out.String()[from:], err
}

// l26cRun is one class's (or R's) cells and outputs, keyed by probe.
type l26cRun struct {
	cells, outs map[string]string
}

func newL26cRun() l26cRun { return l26cRun{cells: map[string]string{}, outs: map[string]string{}} }

// xmlMode types entry at the CLI, and where a hello comes back, sends the
// client hello and each RPC, each read to its `</rpc-reply>`. The session is
// NETCONF afterwards, and the caller closes it.
func l26cXMLMode(c *cliConn, entry string, r l26cRun) {
	key := "entry: " + entry
	from := len(c.out.String())
	if err := c.send(entry); err != nil {
		r.cells[key] = "not observed"
		return
	}
	out, err := c.expectFrom(from, junosPer, "</hello>", junosOpPrompt)
	if err == nil && !strings.Contains(out, "</hello>") {
		// The prompt came back: settle, so a refusal after it is read whole.
		junosSettle(c)
		out = c.out.String()[from:]
	}
	r.outs[key] = out
	r.cells[key] = l26cEntryCell(out)
	if err != nil {
		r.cells[key] = "not observed"
	}
	if r.cells[key] != "hello" {
		return
	}
	if _, err := fmt.Fprint(c.in, junosL26cClientHello+"\n"); err != nil {
		return
	}
	for _, rpc := range junosL26cRPCs {
		k := entry + ": " + rpc.name
		from := len(c.out.String())
		if _, err := fmt.Fprint(c.in, rpc.body+"]]>]]>\n"); err != nil {
			r.cells[k] = "not observed"
			return
		}
		reply, err := c.expectFrom(from, 60*time.Second, "</rpc-reply>")
		r.outs[k] = reply
		r.cells[k] = l26cRPCCell(reply, rpc.evidence)
		if err != nil {
			r.cells[k] = "not observed"
			return
		}
	}
}

// l26cCLI types the plain probes in an open CLI session: show version and
// show configuration (probe 6), op's completion and op url (4), start shell
// (5), typing only `exit` in a shell.
func (l *lab) l26cCLI(c *cliConn, r l26cRun) {
	for _, p := range []struct{ cmd, evidence string }{{"show version", "Junos:"}, {"show configuration", "host-name"}} {
		out, err := l26cSend(c, p.cmd)
		r.outs[p.cmd] = out
		r.cells[p.cmd] = l26cCLICell(out, p.evidence)
		if err != nil {
			r.cells[p.cmd] = "not observed"
		}
	}
	w := &keywordWalk{c: c, logf: func(string, ...any) {}, prompt: "@" + junosHost + "> "}
	if words, ph, err := w.completion("op"); err != nil {
		r.cells["op ?"] = "not observed"
	} else {
		r.cells["op ?"] = fmt.Sprintf("%d words, placeholder %v", len(words), ph)
		r.outs["op ?"] = strings.Join(words, " ")
	}
	junosSettle(c)
	out, err := l26cSend(c, "op url /var/tmp/p49-none.slax")
	r.outs["op url"] = out
	r.cells["op url"] = l26cOpURLCell(out)
	if err != nil {
		r.cells["op url"] = "not observed"
	}
	from := len(c.out.String())
	if err := c.send("start shell"); err == nil {
		_, err = c.expectFrom(from, junosPer, junosOpPrompt, "% ", "$ ")
		junosSettle(c)
		out := c.out.String()[from:]
		r.outs["start shell"] = out
		r.cells["start shell"] = l26cShellCell(out)
		if err != nil {
			r.cells["start shell"] = "not observed"
		}
		if r.cells["start shell"] == "shell" {
			from := len(c.out.String())
			c.send("exit")
			back, _ := c.expectFrom(from, junosPer, junosOpPrompt)
			r.outs["start shell"] += "\n[exit typed]\n" + back
		}
	}
}

// l26cPort22 dials the NETCONF subsystem on port 22 with the next token (or
// break-glass where user is set), sends get-software-information where a
// hello comes back, and records the dial's outcome: hello, login refused,
// refused (the channel closed after port49d permitted the session), or not
// observed.
func (l *lab) l26cPort22(t *testing.T, user, secret string, token bool, r l26cRun) {
	t.Helper()
	off := l.mark()
	if token {
		user, secret = l.nextLogin(t)
	}
	n, hello, err := l.netconfDialPort(user, secret, "22")
	if err != nil {
		permitted := !token
		if token {
			permitted = sessionPermitted(l.drainRecords(off, 10*time.Second))
		}
		cell := "not observed"
		switch {
		case isAuthRejection(err):
			cell = "login refused"
		case permitted && (strings.Contains(err.Error(), "the NETCONF channel closed:") ||
			strings.Contains(err.Error(), "subsystem request failed")):
			cell = "refused"
		}
		r.cells["port 22"] = cell
		r.outs["port 22"] = oneLine(err.Error())
		return
	}
	defer n.Close()
	r.cells["port 22"] = "hello"
	r.outs["port 22"] = firstLines(hello, 5)
	reply, err := n.rpc(1, "<get-software-information/>")
	r.outs["port 22: get-software-information"] = firstLines(reply, 10)
	r.cells["port 22: get-software-information"] = l26cRPCCell(reply, "<software-information")
	if err != nil {
		r.cells["port 22: get-software-information"] = "not observed"
	}
}

func TestL26cJunosRPCReach(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		stop := l.capture(t, "L26c")
		defer stop()
		commit := l.junosConfigureAdmin(t, junosL26cClass)
		defer l.junosConfigureAdmin(t, junosL26cDelete)
		defer func() {
			if std, err := l.configPath(); err == nil {
				if err := l.restart(std); err != nil {
					t.Errorf("could not put port49d back on the lab config: %v", err)
				}
			}
		}()
		runs := map[string]l26cRun{"R": newL26cRun()}
		breakglass := func(fn func(c *cliConn)) {
			c, err := l.junosCLI(breakglassUser, breakglassPassword)
			if err != nil {
				t.Fatalf("no break-glass CLI: %v", err)
			}
			defer c.Close()
			if err := junosPrepare(c); err != nil {
				t.Fatalf("set cli screen-length 0 not observed within %s: %v", junosPer, err)
			}
			fn(c)
		}

		// The xml-mode forms completion reports, over break-glass.
		var forms []string
		entries := []string{junosL26cXMLMode}
		breakglass(func(c *cliConn) {
			w := &keywordWalk{c: c, logf: t.Logf, prompt: "@" + junosHost + "> "}
			for _, p := range []string{"xml-mode", "xml-mode netconf"} {
				words, ph, err := w.completion(p)
				forms = append(forms, fmt.Sprintf("`%s ?`: %v, placeholder %v, err %v", p, words, ph, err))
				if p == "xml-mode" && slices.Contains(words, "netconf") {
					entries = append(entries, "xml-mode netconf")
				}
			}
			junosSettle(c)
			l.l26cCLI(c, runs["R"])
			l26cXMLMode(c, junosL26cXMLMode, runs["R"])
		})
		for _, e := range entries[1:] {
			breakglass(func(c *cliConn) { l26cXMLMode(c, e, runs["R"]) })
		}

		// P, F and C: one session for the CLI probes and the canonical
		// entry, one per other entry.
		for _, v := range junosL26cVariants {
			r := newL26cRun()
			runs[v.name] = r
			c, run, _ := l.junosLogin(t, v.name, v.attrs)
			if c == nil {
				t.Fatalf("%s: the session did not open, so nothing was measured: %s", v.name, run.loginErr)
			}
			r.outs["show cli authorization"] = run.auth
			l.l26cCLI(c, r)
			l26cXMLMode(c, junosL26cXMLMode, r)
			c.Close()
			for _, e := range entries[1:] {
				c, run, _ := l.junosLogin(t, v.name+" "+e, v.attrs)
				if c == nil {
					t.Fatalf("%s: the session did not open: %s", v.name, run.loginErr)
				}
				l26cXMLMode(c, e, r)
				c.Close()
			}
		}

		// Port 22, with the services branch M leaves: netconf ssh deleted.
		services := l.junosConfigureAdmin(t, []string{"delete system services netconf"})
		defer l.junosConfigureAdmin(t, []string{"set system services netconf ssh"})
		var servicesNow string
		breakglass(func(c *cliConn) {
			servicesNow, _ = c.sendExpect("show configuration system services | display set", junosPer, junosOpPrompt)
		})
		l.l26cPort22(t, breakglassUser, breakglassPassword, false, runs["R"])
		for _, v := range junosL26cVariants {
			cfg, err := l.derivedConfigCmd("junos-l26c-"+l16Slug(v.name), v.attrs, "", "")
			if err == nil {
				err = l.restart(cfg)
			}
			if err != nil {
				t.Fatalf("%s: port49d with %s: %v", v.name, v.attrs, err)
			}
			l.l26cPort22(t, "", "", true, runs[v.name])
		}

		// The verdict.
		probes := []string{"op url", "start shell", "port 22", "port 22: get-software-information"}
		for _, e := range entries {
			probes = append(probes, "entry: "+e)
			for _, rpc := range junosL26cRPCs {
				probes = append(probes, e+": "+rpc.name)
			}
		}
		reachable, isolated, why := l26cVerdict(runs, probes)
		for _, w := range why {
			if strings.HasPrefix(w, "not observed") {
				t.Error(w)
			}
		}

		var b strings.Builder
		fmt.Fprintf(&b, "The class was committed: %s.\n\n```\n%s\n```\n\n", commitWord(commit), strings.Join(junosL26cClass, "\n"))
		b.WriteString("| class | reply | why |\n|---|---|---|\n")
		for _, v := range junosL26cVariants {
			fmt.Fprintf(&b, "| %s | `%s` | %s |\n", v.name, tableCell(v.attrs), v.why)
		}
		b.WriteString("| R | break-glass, local | every permission: shows each probe runs at all |\n\n")
		fmt.Fprintf(&b, "xml-mode completion (break-glass): %s. Entries tried: `%s`.\n\n", strings.Join(forms, "; "),
			strings.Join(entries, "`, `"))
		fmt.Fprintf(&b, "Port 22 was measured after `delete system services netconf` (commit: %s); the services then:\n\n```\n%s\n```\n\n",
			commitWord(services), servicesNow)
		b.WriteString("| probe | P | F | C | R |\n|---|---|---|---|---|\n")
		for _, p := range append([]string{"show version", "show configuration", "op ?"}, probes...) {
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", tableCell(p), cellOr(runs["P"], p), cellOr(runs["F"], p),
				cellOr(runs["C"], p), cellOr(runs["R"], p))
		}
		fmt.Fprintf(&b, "\n### Read off the table\n\n- RPC reachable from projected CLI: %v\n- every P and F refusal isolated: %v\n", reachable, isolated)
		for _, w := range why {
			fmt.Fprintf(&b, "- %s\n", w)
		}
		for _, name := range []string{"P", "F", "C", "R"} {
			fmt.Fprintf(&b, "\n### %s\n", name)
			keys := make([]string, 0, len(runs[name].outs))
			for k := range runs[name].outs {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				fmt.Fprintf(&b, "\n`%s`:\n\n```\n%s\n```\n", k, firstLines(orEmpty([]string{runs[name].outs[k]}, 0), 20))
			}
		}
		l.result(t, "L26c", "Whether a projected Junos CLI session reaches an RPC past its denies: `xml-mode netconf "+
			"need-trailer`, the NETCONF subsystem on port 22 with `netconf ssh` deleted, `op url`, and `start shell`, "+
			"under a projected class, the fail-closed reply and a control (Task 13a review I1; gates Task 14's branch M).",
			b.String())
	})
}

func cellOr(r l26cRun, k string) string {
	if c, ok := r.cells[k]; ok {
		return c
	}
	return "—"
}

// l26cReached is a cell that reaches past a deny: an RPC result, a hello, a
// shell, `op url` taken to the file.
func l26cReached(cell string) bool {
	return cell == "result" || cell == "hello" || cell == "shell" || cell == "accepted"
}

// l26cVerdict reads the table: an RPC is reachable from a projected CLI where
// any probe reached past the deny in P or F. It is not where every P and F
// cell is a refusal, each isolated by C reaching (or R reaching where C's
// bits refuse it too, the refusal then the bits', not the deny's), or where
// neither C nor R reaches it (the probe runs nowhere). A probe not typed in a
// class (a hello never came, so no RPC) takes its entry's verdict. Anything
// else is not observed.
func l26cVerdict(runs map[string]l26cRun, probes []string) (reachable, isolated bool, why []string) {
	isolated = true
	for _, p := range probes {
		for _, cls := range []string{"P", "F"} {
			cell, ok := runs[cls].cells[p]
			if !ok {
				continue // not typed: its entry was refused
			}
			if l26cReached(cell) {
				reachable = true
				why = append(why, fmt.Sprintf("reached: %s in %s (%s)", p, cls, cell))
				continue
			}
			if cell == "not observed" && runs["C"].cells[p] == "not observed" && l26cReached(runs["R"].cells[p]) {
				// The class's bits answer it as in C, which neither runs nor
				// refuses it; R reaches it: a result of the bits, recorded, not
				// a failure (the controller's I-5 ruling on L26b).
				why = append(why, fmt.Sprintf("bits-limited: %s neither ran nor was refused in %s, as in C; reached in R", p, cls))
				continue
			}
			if cell != "refused" && cell != "login refused" {
				isolated = false
				why = append(why, fmt.Sprintf("not observed: %s in %s (%s)", p, cls, cell))
				continue
			}
			cc, rc := runs["C"].cells[p], runs["R"].cells[p]
			switch {
			case l26cReached(cc):
			case l26cReached(rc):
				why = append(why, fmt.Sprintf("%s refused in %s and C alike (the bits), reached in R", p, cls))
			case !l26cReached(rc) && rc != "not observed" && rc != "":
				why = append(why, fmt.Sprintf("%s runs nowhere: refused in R too (%s)", p, rc))
			default:
				isolated = false
				why = append(why, fmt.Sprintf("not observed: %s refused in %s, and neither C (%s) nor R (%s) shows it runs", p, cls, cc, rc))
			}
		}
	}
	return reachable, isolated, why
}
