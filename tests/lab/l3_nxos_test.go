//go:build lab

package lab

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// L3 on NX-OS, re-measured — the row was closed on 2026-09-20 on a note that
// did not show its working, and reopened on 2026-09-21.
//
// What `tests/lab/results/L3-cisco_nxos.md` asserted: "Nexus 9300v 10.4(2)F has
// no enable exchange at all." What it quoted: `% Invalid command at '^'
// marker.` What it did not show: **which command the device was rejecting.**
// `TestL3Enable` types `disable` first — the seeded session is `priv-lvl=15`,
// so `enable` from there is a no-op — and `l3RejectedCommand` matches
// `% Invalid` on that output. So the transcript almost certainly records the
// device rejecting `disable`, and `enable` was very likely never typed at all.
// A register row was closed on that, and had to be reopened.
//
// This test types the commands the claim is about, one at a time, and records
// each one's exact reply beside the exact command:
//
//	disable
//	enable
//	enable 15
//
// twice — once with the device as `tests/lab/configs/nxos-startup.cfg` leaves
// it, and once with `feature privilege` and an `enable secret` configured,
// which is the configuration NX-OS documents an exec `enable` under. Between
// the two phases it also logs a token user in BELOW privilege 15, because an
// operator already at 15 has nothing to raise — and **what reply attributes
// achieve that on NX-OS is itself one of the findings**, since NX-OS assigns
// privilege by role rather than by level.
//
// Every negative here goes through negativeFinding, which will not render
// without the command and the reply. That is the whole point of the re-test.
func TestL3NXOSEnable(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "cisco_nxos" {
			t.Skipf("this is the NX-OS correction to L3; %s is measured by TestL3Enable", l.p.name)
		}
		stop := l.capture(t, "L3-nxos")
		defer stop()

		var b strings.Builder
		b.WriteString(l3nxPreamble)

		// Phase 1 — the device exactly as the startup config leaves it.
		b.WriteString("\n## Phase 1 — as `tests/lab/configs/nxos-startup.cfg` leaves the device\n\n")
		b.WriteString("`feature privilege` is not configured and there is no `enable secret`.\n\n")
		p1 := l.l3nxTyped(t, `["priv-lvl=15", "shell:roles*network-admin"]`)
		b.WriteString(p1.render())
		b.WriteString(l3nxVerdict(t, p1, "without `feature privilege`"))

		// Phase 2 — the configuration NX-OS documents an enable under, and a
		// session that is actually below 15 so there is something to raise.
		b.WriteString("\n## Phase 2 — with `feature privilege` and an `enable secret`\n\n")
		restore := l.l3nxEnableFeature(t)
		defer restore(t)

		// Two attempts at putting the operator below 15, because which one
		// works is a finding rather than a given. `priv-lvl=1` is the
		// privilege-level path; `shell:roles*priv-1` is the role NX-OS
		// creates for level 1 once `feature privilege` is on.
		for _, attempt := range []struct{ label, attrs string }{
			{"`priv-lvl=1`", `["priv-lvl=1"]`},
			{"`shell:roles*priv-1`", `["priv-lvl=1", "shell:roles*priv-1"]`},
		} {
			fmt.Fprintf(&b, "\n### Attempt to land below privilege 15 with %s\n\n", attempt.label)
			p := l.l3nxTyped(t, attempt.attrs)
			b.WriteString(p.render())
			b.WriteString(l3nxVerdict(t, p, "with `feature privilege`, session attributes "+attempt.label))
		}

		l.result(t, "L3-nxos", l3nxClaim, b.String())
	})
}

const l3nxClaim = "Whether the Nexus 9300v has an exec `enable` at all, under the lab's own configuration and " +
	"under `feature privilege`; what reply attributes put an NX-OS session below privilege 15; and what " +
	"the wire exchange carries when an enable does happen — username form, `service`, `port`, `rem_addr`, " +
	"`priv_lvl`. This supersedes `tests/lab/results/L3-cisco_nxos.md`, which asserted that no enable " +
	"exists while quoting a reply to a command it did not name."

const l3nxPreamble = "Each command below is typed on its own and its reply is recorded beside it. The note " +
	"this supersedes said `% Invalid command at '^' marker.` without saying which command was rejected; the " +
	"test that wrote it types `disable` first, so that reply was very probably `disable`'s. Here `disable`, " +
	"`enable` and `enable 15` are separate rows and each carries its own transcript.\n"

// l3nxTyped is one session: log in with these reply attributes, record the
// prompt the login produced, then type the three commands.
type l3nxTyped struct {
	attrs    string
	loginErr string
	prompt   string
	whoami   string
	typed    []l3nxCommand
	enables  []map[string]any
	recs     []map[string]any
}

type l3nxCommand struct {
	cmd string
	out string
}

func (p l3nxTyped) render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Reply attributes: `%s`\n\n", p.attrs)
	if p.loginErr != "" {
		fmt.Fprintf(&b, "**The session never opened.**\n\n```\n%s\n```\n\n", p.loginErr)
		return b.String()
	}
	fmt.Fprintf(&b, "The prompt the login produced: `%s`\n\n", p.prompt)
	if p.whoami != "" {
		fmt.Fprintf(&b, "`show user-account`:\n\n```\n%s\n```\n\n", strings.TrimRight(p.whoami, "\n"))
	}
	for _, c := range p.typed {
		fmt.Fprintf(&b, "Typed:\n\n```\n%s\n```\n\nThe device replied:\n\n```\n%s\n```\n\n",
			c.cmd, strings.TrimRight(c.out, "\n"))
	}
	if len(p.enables) == 0 {
		b.WriteString("**No authentication record beyond the login reached port49 in this session**, so no " +
			"enable exchange was put on the wire by any of the three commands.\n\n")
	} else {
		b.WriteString("Authentication records beyond the login — the enable exchange:\n\n```\n")
		for _, r := range p.enables {
			s := sub(r, "session")
			fmt.Fprintf(&b, "event=%s verdict=%s reason=%s user=%q port=%q rem_addr=%q priv=%v method=%s\n",
				str(r, "event"), str(r, "verdict"), str(r, "reason"), str(s, "username"),
				str(s, "port"), str(s, "rem_addr"), s["privilege"], str(sub(r, "auth"), "method"))
		}
		b.WriteString("```\n\n")
	}
	return b.String()
}

func (l *lab) l3nxTyped(t *testing.T, attrs string) l3nxTyped {
	t.Helper()
	p := l3nxTyped{attrs: attrs}
	cfg, err := l.derivedConfig("l3nx-"+l16Slug(attrs), attrs, "")
	if err != nil {
		t.Fatalf("derive the config for %s: %v", attrs, err)
	}
	if err := l.stopDaemon(); err != nil {
		t.Fatalf("stopping the daemon: %v", err)
	}
	if err := l.startDaemonWith(cfg, true); err != nil {
		t.Fatalf("starting the daemon: %v", err)
	}

	off := l.mark()
	user, secret := l.nextLogin(t)
	c, err := l.nxosCLI(user, secret)
	if err != nil {
		p.loginErr = err.Error()
		p.recs = l.drainRecords(off, 5*time.Second)
		return p
	}
	p.prompt = c.prompt
	if out, err := nxosShow(c, "show user-account"); err == nil {
		p.whoami = l16TrimEcho(out, "show user-account")
	}

	// The three commands, each on its own, each with its own transcript. The
	// expect set is wide on purpose: a password prompt, a refusal, a new
	// prompt and a marker line are all possible answers and all are findings,
	// so none of them may be the only thing waited for.
	for _, cmd := range []string{"disable", "enable", "enable 15"} {
		out, _ := c.sendExpect(cmd, 25*time.Second,
			"assword", "Invalid", "invalid", "%", "denied", "#", ">", "^")
		got := l16TrimEcho(out, cmd)
		if strings.TrimSpace(got) == "" {
			got = emptyDeviceReply
		}
		p.typed = append(p.typed, l3nxCommand{cmd: cmd, out: got})
		// If the device asked for a password, answer it: an enable that reaches
		// a password prompt is the exchange this row is about, and leaving the
		// prompt unanswered would leave the session wedged for the next command.
		if strings.Contains(got, "assword") {
			pw, _ := c.sendExpect(enableSecret, 25*time.Second, "#", ">", "denied", "Invalid", "%", "fail")
			p.typed = append(p.typed, l3nxCommand{
				cmd: "(the enable password, at the prompt above)",
				out: strings.Trim(l16TrimEcho(pw, enableSecret), "\r\n"),
			})
		}
	}
	c.Close()

	p.recs = l.drainRecords(off, 10*time.Second)
	p.enables = l3EnableRecords(p.recs, user)
	return p
}

// l3nxEnableFeature turns on `feature privilege` and sets an enable secret,
// returning a function that removes both.
func (l *lab) l3nxEnableFeature(t *testing.T) func(*testing.T) {
	t.Helper()
	apply := func(t *testing.T, lines ...string) {
		t.Helper()
		l.withAdminCLI(t, func(l *lab) (*cliConn, error) {
			return l.nxosCLI(breakglassUser, breakglassPassword)
		}, func(c *cliConn) error {
			if out, err := nxosConfigure(c, lines...); err != nil {
				return fmt.Errorf("%v: %w\n%s", lines, err, out)
			}
			t.Logf("cisco_nxos: applied %v", lines)
			return nil
		})
	}
	// The enable secret is the published lab break-glass password, the same
	// constant IOS-XE's enable fallback uses. Nothing here is a secret.
	apply(t, "feature privilege", "enable secret 0 "+enableSecret)
	return func(t *testing.T) {
		apply(t, "no enable secret", "no feature privilege")
	}
}

// l3nxVerdict turns one session's transcripts into a claim, and routes the
// negative through negativeFinding so it cannot be written without them.
func l3nxVerdict(t *testing.T, p l3nxTyped, context string) string {
	t.Helper()
	if p.loginErr != "" {
		return "This session never opened, so it says nothing about `enable` on this platform.\n\n"
	}
	var enableCmd, enableOut string
	for _, c := range p.typed {
		if c.cmd == "enable" {
			enableCmd, enableOut = c.cmd, c.out
		}
	}
	if enableCmd == "" {
		t.Fatalf("the session typed no `enable` at all, which is the defect this test exists to correct")
	}
	if len(p.enables) > 0 {
		return fmt.Sprintf("**An enable exchange DOES exist %s**: %d authentication record(s) beyond the "+
			"login reached port49, and their fields are above. Compare the username there with the login's: "+
			"the operator's own name means `(nas, username)` is not weakened by enable on this platform "+
			"(§13, decision 15).\n\n", context, len(p.enables))
	}
	rejected := l3RejectedCommand(enableOut)
	claim := fmt.Sprintf("typing `enable` %s produced no TACACS+ authentication exchange: port49 received "+
		"no authentication record for this session beyond the login itself.", context)
	if rejected {
		claim = fmt.Sprintf("the device rejects `enable` outright %s, so there is no enable exchange to "+
			"measure on this platform under that configuration.", context)
	}
	return negativeFinding{
		Claim: claim,
		Sent:  enableCmd,
		Got: strings.TrimRight(enableOut, "\n") +
			"\n\n(and no authentication record beyond the login reached the decision log in this session's window)",
	}.render(t) + "\n"
}
