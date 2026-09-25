//go:build lab

package lab

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestL12JunosNetconf asks whether a wire deny-commands, and the fail-closed
// reply, bind a NETCONF RPC (spec §15 L12; decision 27; plan 5b pre-flight
// B1). The token that opens an SSH CLI also opens `ssh -s netconf`, and the
// session gets the same reply (L14). If Junos applies deny-commands to CLI
// command lines only, every deny port49 sends is walked around by the RPC
// that does the same thing: `<get-configuration>` past `deny show
// configuration **`. The answer can change set 1.1.0 (Task 14, branch M), so
// it is measured here, before the code is final.
//
// Four sessions, each a NETCONF session opened with a fresh seeded token
// under its own reply, each sending the RPCs of junosNetconfRPCs, the
// equivalents of denied commands: `<get-configuration/>` whole and filtered
// and `<command>show configuration</command>` (`show configuration`), and
// `<get-software-information/>` (`show version`). The control's class holds
// view and view-configuration and no regex, so every one runs. Then the same class
// under a deny naming both commands, as the generator renders it; the
// fail-closed reply under local_user_name (no template: the `remote` user's
// class, which in the lab holds the same bits); and the fail-closed reply
// under user_permissions, the same bits sent over a bitless template. Every
// read has a deadline (the hello 45 s, each RPC 60 s); a reply that is
// neither the RPC's output nor an `<rpc-error>` is not observed and fails the
// test. Four seeded tokens.

var junosNetconfClass = []string{
	"set system login class p49-nc-ro permissions [ view view-configuration ]",
	"set system login user p49-nc-ro class p49-nc-ro",
	"set system login class p49-nc-none idle-timeout 60",
	"set system login user p49-nc-none class p49-nc-none",
}

var junosNetconfDelete = []string{"delete system login user p49-nc-ro", "delete system login class p49-nc-ro",
	"delete system login user p49-nc-none", "delete system login class p49-nc-none"}

// junosNetconfDeny names `show configuration **` and `show version` as the
// generator renders a deny (ruleERE, as fixed in eaf7975: a leading ` *`,
// words joined by ` +`, the tail ` *(\|.*)?`).
const junosNetconfDeny = `^( *show +configuration( .*)? *(\\|.*)?| *show +version *(\\|.*)?)$`

var junosNetconfVariants = []junosVariant{
	{"control", `["local-user-name=p49-nc-ro"]`, "view and view-configuration, no regex: every RPC runs"},
	{"deny", `["local-user-name=p49-nc-ro", "deny-commands=` + junosNetconfDeny + `"]`,
		"the same class under a deny naming both commands"},
	{"fail-closed, local_user_name", `["deny-commands=^.*$"]`,
		"decision 26's reply with no template: the session lands in remote's class"},
	{"fail-closed, user_permissions", `["local-user-name=p49-nc-none", "user-permissions=view view-configuration", "deny-commands=^.*$"]`,
		"decision 26's reply with bits over a bitless template"},
}

// junosNetconfPairs is each fail-closed variant's paired control: the same
// template and class with the deny left out (the lead's ruling, 2026-09-25).
// A fail-closed session whose channel closes before the hello is refused only
// where its paired control, opened directly before and after it, got a hello.
var junosNetconfPairs = map[string]string{
	"fail-closed, local_user_name":  `[]`,
	"fail-closed, user_permissions": `["local-user-name=p49-nc-none", "user-permissions=view view-configuration"]`,
}

// junosNetconfClosed is the cell of a session the device closed before its
// hello, isolated by its paired control.
const junosNetconfClosed = "refused: the channel closed before hello"

// junosNetconfRPCs are the RPCs sent in each session, each with what its
// output holds and the CLI command it stands for: the configuration whole and
// filtered, the CLI text itself over `<command>` (re-pre-flight R-M3), and the
// software version. The configuration's evidence is the host name, which each
// form prints.
var junosNetconfRPCs = []struct{ rpc, evidence, command string }{
	{"<get-configuration/>", "host-name", "show configuration"},
	{"<get-configuration><configuration><system/></configuration></get-configuration>", "host-name",
		"show configuration system"},
	{"<command>show configuration</command>", "host-name", "show configuration"},
	{"<get-software-information/>", "<software-information", "show version"},
}

// netconfCell is one RPC's outcome: ran, refused, or not observed.
func netconfCell(reply, evidence string) string {
	switch {
	case strings.Contains(reply, "<rpc-error>"):
		return "refused"
	case strings.Contains(reply, evidence):
		return "ran"
	}
	return "not observed"
}

func TestL12JunosNetconf(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		if netconfPort(l.p) == "" {
			t.Fatalf("%s: this lab does not enable NETCONF, so nothing can be measured", l.p.name)
		}
		stop := l.capture(t, "L12-netconf")
		defer stop()
		commit := l.junosConfigureAdmin(t, junosNetconfClass)
		defer l.junosConfigureAdmin(t, junosNetconfDelete)
		defer func() {
			if std, err := l.configPath(); err == nil {
				if err := l.restart(std); err != nil {
					t.Errorf("could not put port49d back on the lab config: %v", err)
				}
			}
		}()
		cells := make([][]string, len(junosNetconfVariants))
		replies := make([][]string, len(junosNetconfVariants))
		// dial opens a NETCONF session under attrs with the next seeded
		// token, and says what port49d recorded for it where it did not open.
		dial := func(name, attrs string) (*netconfConn, string, error) {
			cfg, err := l.derivedConfigCmd("junos-nc-"+l16Slug(name), attrs, "", "")
			if err == nil {
				err = l.restart(cfg)
			}
			if err != nil {
				t.Fatalf("%s: port49d with %s: %v", name, attrs, err)
			}
			off := l.mark()
			user, secret := l.nextLogin(t)
			n, hello, err := l.netconfDial(user, secret)
			if err == nil {
				return n, hello, nil
			}
			var events []string
			for _, rec := range l.drainRecords(off, 10*time.Second) {
				events = append(events, str(rec, "event")+" "+str(rec, "decision")+" "+str(rec, "reason"))
			}
			return nil, "", fmt.Errorf("%s: %v (%s); port49d recorded %v", user, err, oneLine(hello), events)
		}
		for i, v := range junosNetconfVariants {
			pair, paired := junosNetconfPairs[v.name]
			// The paired control opens the channel under the same template
			// and class, the deny left out, directly before and after the
			// session it isolates.
			var pairs []string
			openPair := func(when string) bool {
				if !paired {
					return false
				}
				n, hello, err := dial(v.name+" pair "+when, pair)
				if err != nil {
					pairs = append(pairs, fmt.Sprintf("paired control %s (`%s`): no hello: %v", when, pair, err))
					return false
				}
				n.Close()
				pairs = append(pairs, fmt.Sprintf("paired control %s (`%s`): hello (%d bytes)", when, pair, len(hello)))
				return true
			}
			before := openPair("before")
			n, _, err := dial(v.name, v.attrs)
			if err != nil {
				after := openPair("after")
				var devLog string
				l.withAdminCLI(t, func(l *lab) (*cliConn, error) {
					return l.junosCLI(breakglassUser, breakglassPassword)
				}, func(c *cliConn) error {
					if err := junosPrepare(c); err != nil {
						return err
					}
					out, err := c.sendExpect(`show log messages | last 60 | no-more`,
						junosPer, junosOpPrompt)
					devLog = out
					return err
				})
				// A channel that closes before the hello is a refusal only
				// where the paired control proved it opens without the deny,
				// both before and after; otherwise it measured nothing.
				cell := "not observed"
				if before && after {
					cell = junosNetconfClosed
				} else {
					t.Errorf("%s: the NETCONF session did not open, and no paired control proved that it opens "+
						"without the deny, so nothing was measured: %v; %v", v.name, err, pairs)
				}
				why := fmt.Sprintf("no session: %v\n%s\n\nthe device's log:\n%s", err, strings.Join(pairs, "\n"), devLog)
				for range junosNetconfRPCs {
					cells[i] = append(cells[i], cell)
					replies[i] = append(replies[i], why)
				}
				continue
			}
			for k, r := range junosNetconfRPCs {
				reply, err := n.rpc(k+1, r.rpc)
				cell := netconfCell(reply, r.evidence)
				if err != nil || cell == "not observed" {
					t.Errorf("%s: %s not observed: %v %s", v.name, r.rpc, err, oneLine(reply))
					cell = "not observed"
				}
				cells[i] = append(cells[i], cell)
				replies[i] = append(replies[i], reply)
			}
			n.Close()
			if paired && !openPair("after") {
				t.Logf("%s: the paired control after it did not open: %v", v.name, pairs)
			}
		}
		ranControl := !slices.ContainsFunc(cells[0], func(c string) bool { return c != "ran" })
		if !ranControl {
			t.Errorf("the control did not run every RPC, so no deny is measured: %v", cells[0])
		}
		bound := ranControl
		for _, row := range cells[1:] {
			for _, c := range row {
				bound = bound && (c == "refused" || c == junosNetconfClosed)
			}
		}
		var b strings.Builder
		fmt.Fprintf(&b, "The classes were committed: %s.\n\n```\n%s\n```\n\n", commitWord(commit),
			strings.Join(junosNetconfClass, "\n"))
		b.WriteString("| session | reply | why |")
		for _, r := range junosNetconfRPCs {
			fmt.Fprintf(&b, " %s |", tableCell(r.rpc))
		}
		b.WriteString("\n|---|---|---|" + strings.Repeat("---|", len(junosNetconfRPCs)) + "\n")
		for i, v := range junosNetconfVariants {
			// A cell whose control did not run the RPC isolates nothing.
			row := slices.Clone(cells[i])
			for k := range row {
				if i > 0 && cells[0][k] != "ran" {
					row[k] = "not isolated (" + row[k] + ")"
				}
			}
			fmt.Fprintf(&b, "| %s | `%s` | %s | %s |\n", v.name, tableCell(v.attrs), v.why, strings.Join(row, " | "))
		}
		fmt.Fprintf(&b, "\n### Read off the table\n\n- deny-commands and the fail-closed reply bind NETCONF RPCs: %v "+
			"(true only where the control ran every RPC and every other session refused every one; set 1.1.0 "+
			"takes it as bound only where both images say true)\n", bound)
		for i, v := range junosNetconfVariants {
			fmt.Fprintf(&b, "\n### %s\n", v.name)
			for k, r := range junosNetconfRPCs {
				reply := firstLines(replies[i][k], 30)
				if strings.HasPrefix(replies[i][k], "no session: ") {
					reply = replies[i][k] // why it did not open, whole
				}
				fmt.Fprintf(&b, "\n`%s`:\n\n```\n%s\n```\n", r.rpc, orEmpty([]string{reply}, 0))
			}
		}
		l.result(t, "L12-netconf", "Over TACACS+ on `junos-exec`: whether a wire deny-commands, and decision 26's "+
			"fail-closed reply, bind a NETCONF RPC opened with the same token and reply, "+
			"`<get-configuration>` and `<get-software-information>` beside `show configuration` and `show version` "+
			"(spec §15 L12; decision 27).", b.String())
	})
}

// firstLines is at most n lines of s: an RPC's output is the configuration,
// and the note needs only enough of it to show what ran.
func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[:n], "\n") + fmt.Sprintf("\n… (%d more lines)", len(lines)-n)
}
