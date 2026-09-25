//go:build lab

package lab

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	adapter "github.com/rhwendt/port49/internal/platform"
)

// TestL23InertBesideReadonly re-measures L22's inert candidates beside
// readonly's reply, where a raise shows: beside admin's, the session already
// holds everything, so an attribute that raised it would look inert (5a final
// review M3; spec §15 L23). A candidate is inert here only where the session
// opened with readonly's identity, the same reach for both ceiling commands,
// and a `show version` port49 permitted. Every command has adapterVariant's
// deadline; one that did not finish is not observed and fails the test.
func TestL23InertBesideReadonly(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "arista_eos" && l.p.name != "cisco_nxos" {
			t.Skip("EOS and NX-OS: IOS-XE holds every candidate bearing (L22-cisco_iosxe.md)")
		}
		d, _ := adapter.DialectFor(l.p.name)
		stop := l.capture(t, "L23")
		defer stop()
		defer func() {
			if std, err := l.configPath(); err == nil {
				if err := l.restart(std); err != nil {
					t.Errorf("could not put port49d back on the lab config: %v", err)
				}
			}
		}()
		readonly, _ := d.Render("readonly")
		control := l.adapterVariant(t, "l23-readonly", readonly)
		if control.err != nil || len(control.unobserved) > 0 || !control.showVersion {
			t.Fatalf("readonly's own reply did not give a session to compare against: %+v", control)
		}
		var b strings.Builder
		fmt.Fprintf(&b, "Control, readonly's reply `%s`: identity `%s`, `clear counters` %s, `configure terminal` %s, "+
			"`show version` %s.\n\n| attribute | session | identity | `clear counters` | `configure terminal` | "+
			"`show version` | inert |\n|---|---|---|---|---|---|---|\n", strings.Join(readonly, "`, `"), control.identity,
			control.reach("clear counters", control.clear), control.reach("configure terminal", control.cfg),
			control.permit(control.showVersion))
		for _, a := range inertCandidates {
			name := strings.SplitN(a, "*", 2)[0]
			row := l.adapterVariant(t, "l23-"+name, append(slices.Clone(readonly), a))
			if len(row.unobserved) > 0 {
				t.Errorf("%s: not observed: %v", a, row.unobserved)
			}
			inert := row.err == nil && len(row.unobserved) == 0 && row.identity == control.identity &&
				row.clear == control.clear && row.cfg == control.cfg && row.showVersion
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s | %s |\n", a, row.session, row.identity,
				row.reach("clear counters", row.clear), row.reach("configure terminal", row.cfg),
				row.permit(row.showVersion), yesNo(inert))
			if !inert && slices.Contains(d.InertAttributes, name) {
				t.Errorf("%s is listed inert on %s and moved readonly's session: set 1.1.0 lists it bearing "+
					"(plan 5b, Task 14)", name, l.p.name)
			}
		}
		l.result(t, "L23", "Whether home-directory, idletime and timeout, each beside readonly's reply, leave the "+
			"session readonly's: the same identity, the same reach for `clear counters` and `configure terminal`, "+
			"and a permitted `show version` (spec §6, §15 L23; 5a final review M3).", b.String())
	})
}

// TestL25NXOSSystemUser measures the production observation plan 2 left
// unentered: on the N9Kv, a network-operator's bare `show interface` prompts
// for sudo, and cancelling it writes an accounting record under `admin` with
// task_id `vsh.bin.<port>` (roadmap, plan 5). The session is one pty with a
// deadline on every prompt; the records are read off the decision log.
func TestL25NXOSSystemUser(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "cisco_nxos" {
			t.Skip("NX-OS only")
		}
		d, _ := adapter.DialectFor(l.p.name)
		stop := l.capture(t, "L25")
		defer stop()
		readonly, _ := d.Render("readonly")
		quoted := `["` + strings.Join(readonly, `", "`) + `"]`
		cfg, err := l.derivedConfig("l25", quoted, "")
		if err == nil {
			err = l.restart(cfg)
		}
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if std, err := l.configPath(); err == nil {
				if err := l.restart(std); err != nil {
					t.Errorf("could not put port49d back on the lab config: %v", err)
				}
			}
		}()
		off := l.mark()
		user, secret := l.nextLogin(t)
		c, err := l.sshCLI(user, secret)
		if err != nil {
			t.Fatalf("the network-operator session did not open: %v", err)
		}
		defer c.Close()
		prompt := l.p.node + "#"
		if _, err := c.expect(90*time.Second, prompt); err != nil {
			t.Fatalf("no prompt: %v", err)
		}
		const per = 60 * time.Second
		out, err := c.sendExpect("show interface", per, prompt, "assword", "--More--")
		// sent is what was typed, verbatim, for the note: the first run found
		// no sudo prompt on this image and the note still said ^C was sent.
		sent, prompted := "show interface", false
		switch {
		case err != nil:
			t.Fatalf("`show interface` not observed within %s: %v", per, err)
		case strings.Contains(out, "--More--"):
			var more string
			more, err = c.sendExpect("q", per, prompt)
			out += more
			sent += ", then q at the --More-- pager"
		case strings.Contains(out, "assword"):
			// Cancel the sudo prompt, as the production operator did.
			prompted = true
			from := len(c.out.String())
			fmt.Fprint(c.in, "\x03")
			var more string
			more, err = c.expectFrom(from, per, prompt)
			out += more
			sent += ", then ^C at the password prompt"
		}
		if err != nil {
			t.Fatalf("the prompt did not come back within %s: %v", per, err)
		}
		recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
			return slices.ContainsFunc(rs, func(r map[string]any) bool {
				return str(r, "event") == "account" && str(sub(r, "session"), "username") == "admin"
			})
		})
		var admin []string
		for _, r := range recs {
			if str(r, "event") == "account" && str(sub(r, "session"), "username") == "admin" {
				admin = append(admin, fmt.Sprintf("flags %s, task_id `%s`, attribution %s, cmd `%s`", str(r, "flags"),
					str(r, "task_id"), str(r, "attribution"), strings.Join(strs(sub(r, "record"), "raw"), " ")))
			}
		}
		var b strings.Builder
		fmt.Fprintf(&b, "Reply `%s`; the session was %s; typed: %s.\n\n", quoted, user, sent)
		switch {
		case len(admin) > 0:
			fmt.Fprintf(&b, "`show interface` answered:\n\n```\n%s\n```\n\nAccounting records under `admin` after "+
				"it:\n\n- %s\n", orEmpty([]string{out}, 0), strings.Join(admin, "\n- "))
		case prompted:
			b.WriteString(negativeFinding{Claim: "no accounting record under `admin` followed the cancelled sudo in 30s",
				Sent: sent, Got: orEmpty([]string{out}, 0)}.render(t))
		default:
			b.WriteString(negativeFinding{Claim: "a network-operator's bare `show interface` asked for no sudo " +
				"password on this image, so there was no prompt to cancel, and no accounting record under `admin` " +
				"followed in 30s", Sent: sent, Got: orEmpty([]string{out}, 0)}.render(t))
		}
		// Whether a person's session can carry a vsh.bin task_id: an NX-API
		// request, the other path a person's `admin` could take, recorded by
		// its task_id. A system task keyed on the task_id is sound only if no
		// person's record carries one (plan 5b pre-flight M7).
		read := nxapiRead.check(t, l)
		off = l.mark()
		body := nxapiBody("cli_show", "show version")
		if _, err := apiPost("https://"+l.p.addr+"/ins", read.user, read.secret, "application/json", body,
			60*time.Second); err != nil {
			t.Errorf("the NX-API request was not observed: %v", err)
		}
		var tasks []string
		for _, r := range l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
			return slices.ContainsFunc(rs, func(r map[string]any) bool {
				return str(r, "event") == "account" && str(sub(r, "session"), "username") == read.user
			})
		}) {
			if str(r, "event") == "account" && str(sub(r, "session"), "username") == read.user {
				tasks = append(tasks, "`"+str(r, "task_id")+"`")
			}
		}
		if len(tasks) == 0 {
			t.Errorf("no accounting record for the NX-API request in 30s: the task_id it carries is not observed")
		}
		vsh := slices.ContainsFunc(tasks, func(s string) bool { return strings.HasPrefix(s, "`vsh.bin.") })
		fmt.Fprintf(&b, "\nA person's NX-API `cli_show` as %s wrote accounting with task_id %s: a `vsh.bin.` task_id "+
			"on a person's record: %v.\n", read.user, strings.Join(tasks, ", "), vsh)
		l.result(t, "L25", "On the N9Kv, whether a network-operator's bare `show interface` prompts for sudo, "+
			"whether cancelling it writes an accounting record under `admin` with task_id `vsh.bin.<port>`, and "+
			"whether a person's NX-API request can carry such a task_id (spec §5.8, §15 L25).", b.String())
	})
}
