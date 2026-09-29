//go:build lab

package lab

import (
	"fmt"
	"strings"
	"testing"
)

// Whether a wire `deny-commands` reaches a statement typed in configuration
// mode (spec §15 L12), isolated. The wire test's configuration-mode variant
// could not say: its class had no system-control, so Junos hid [system] from
// it with or without the deny. Here both sessions share one class that holds
// system-control, so the statement runs unless the deny refuses it, and the
// deny names only host-name, so a sibling statement in the same hierarchy
// must still run under it: otherwise the refusal is not the deny's.

var junosCfgClass = []string{
	"set system login class p49-l12-sys permissions [ configure view view-configuration system system-control ]",
	"set system login user p49-l12-sys class p49-l12-sys",
}

var junosCfgDelete = []string{"delete system login user p49-l12-sys", "delete system login class p49-l12-sys"}

// junosCfgProbes set only what the device already holds: the host name both
// images carry and the netconf service tests/lab/configs/vjunos-startup.conf
// enables. Neither is committed.
var junosCfgProbes = []junosProbe{{cmd: "configure"}, {cmd: "set system host-name " + junosHost},
	{cmd: "set system services netconf ssh"}, {cmd: "run show system uptime"}, {cmd: "exit configuration-mode"}}

const junosCfgDeny = "^set system host-name( .*)?$"

var junosCfgVariants = []junosVariant{
	{"same class, no deny", `["local-user-name=p49-l12-sys"]`,
		"the control: the class holds system-control, so the statement must run"},
	{"same class, deny host-name", `["local-user-name=p49-l12-sys", "deny-commands=` + junosCfgDeny + `"]`,
		"the same class with a deny naming only the host-name statement"},
}

// junosCfgVerdict reads the two sessions: reached, not reached, or not
// isolated, with the reason. It is isolated only where the control ran both
// statements and, under the deny, the device listed the deny, entered
// configuration mode and ran the sibling statement.
func junosCfgVerdict(control, deny junosRun) string {
	host, sibling := junosCfgProbes[1], junosCfgProbes[2]
	switch {
	case control.loginErr != "" || deny.loginErr != "":
		return "not isolated: a session did not open"
	case !control.runs(host) || !control.runs(sibling):
		return "not isolated: the class without the deny did not run both statements"
	case !strings.Contains(deny.auth, "set system host-name"):
		return "not isolated: the device did not list the deny under `show cli authorization`"
	case !deny.runs(junosCfgProbes[0]) || !deny.runs(sibling):
		return "not isolated: under the deny, configuration mode or the sibling statement was refused"
	case deny.runs(host):
		return "not reached: the statement ran under a deny-commands naming it"
	}
	return "reached: the deny-commands refused the statement it names, and the sibling statement ran"
}

func junosCfgCell(r junosRun, p junosProbe) string {
	switch {
	case r.loginErr != "":
		return "no session"
	case !r.observed(p.cmd):
		return "not observed"
	case r.runs(p):
		return "ran"
	}
	return "refused"
}

// observed reports whether the probe was typed and its prompt came back.
func (r junosRun) observed(cmd string) bool {
	_, ok := r.outs[cmd]
	for _, u := range r.unobserved {
		if u == cmd {
			return false
		}
	}
	return ok
}

func TestL12JunosConfiguration(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "juniper_vjunos-router" && l.p.name != "juniper_vsrx" {
			t.Skip("Junos only")
		}
		stop := l.capture(t, "L12-configuration")
		defer stop()
		// junosConfigureAdmin, keeping the channel's name: the note says which
		// admin CLI configured the class (SSH as breakglass, or the console).
		var admin, commit string
		l.withAdminCLI(t, func(l *lab) (*cliConn, error) {
			return l.junosCLI(breakglassUser, breakglassPassword)
		}, func(c *cliConn) error {
			admin = c.name
			o, err := junosConfigure(c, junosCfgClass...)
			commit = o
			if err != nil {
				return fmt.Errorf("applying %v: %w\n%s", junosCfgClass, err, o)
			}
			return nil
		})
		defer l.junosConfigureAdmin(t, junosCfgDelete)
		defer func() {
			if std, err := l.configPath(); err == nil {
				if err := l.restart(std); err != nil {
					t.Errorf("could not put port49d back on the lab config: %v", err)
				}
			}
		}()
		runs := make([]junosRun, len(junosCfgVariants))
		for i, v := range junosCfgVariants {
			runs[i] = l.junosSession(t, v.name, v.attrs, junosCfgProbes)
			if runs[i].loginErr != "" {
				t.Errorf("%s: the session did not open, so nothing was measured: %s", v.name, runs[i].loginErr)
			}
		}
		verdict := junosCfgVerdict(runs[0], runs[1])
		t.Logf("deny-commands in configuration mode: %s", verdict)
		var b strings.Builder
		fmt.Fprintf(&b, "The admin CLI that configured the class: %s. The class was committed: %s.\n\n", admin,
			commitWord(commit))
		fmt.Fprintf(&b, "```\n%s\n```\n\n", strings.Join(junosCfgClass, "\n"))
		fmt.Fprintf(&b, "| session | reply | why | priv_lvl on the request |\n|---|---|---|---|\n")
		for i, v := range junosCfgVariants {
			fmt.Fprintf(&b, "| %s | `%s` | %s | %s |\n", v.name, tableCell(v.attrs), v.why, runs[i].privilege)
		}
		fmt.Fprintf(&b, "\n| probe | %s | %s |\n|---|---|---|\n", junosCfgVariants[0].name, junosCfgVariants[1].name)
		for _, p := range junosCfgProbes {
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", tableCell(p.cmd), junosCfgCell(runs[0], p), junosCfgCell(runs[1], p))
		}
		fmt.Fprintf(&b, "\n### Read off the table\n\n- deny-commands in configuration mode: %s\n", verdict)
		for i, v := range junosCfgVariants {
			r := runs[i]
			fmt.Fprintf(&b, "\n### %s\n\nReply `%s`.", v.name, v.attrs)
			if r.loginErr != "" {
				fmt.Fprintf(&b, " The session did not open: `%s`.\n", r.loginErr)
				continue
			}
			fmt.Fprintf(&b, " `show cli authorization`:\n\n```\n%s\n```\n", r.auth)
			for _, p := range junosCfgProbes {
				if out, ok := r.outs[p.cmd]; ok {
					fmt.Fprintf(&b, "\n`%s`:\n\n```\n%s\n```\n", p.cmd, orEmpty([]string{out}, 0))
				}
			}
		}
		l.result(t, "L12-configuration", "Over TACACS+ on `junos-exec`: whether a wire `deny-commands` reaches a "+
			"statement typed in configuration mode, isolated: one class holding system-control, with and "+
			"without a deny naming only `set system host-name`, and a sibling statement under the deny "+
			"(spec §15 L12; it replaces the wire test's configuration-mode cell, whose class could not "+
			"modify [system]).", b.String())
	})
}
