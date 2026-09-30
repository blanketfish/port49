//go:build lab

package lab

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// labShell is one interactive session, one command at a time, so something
// can happen between two: ptyCommands' loop as a type.
type labShell struct {
	c       *cliConn
	prompts []string
}

func (l *lab) shell(user, password string) (*labShell, error) {
	c, err := l.sshCLI(user, password)
	if err != nil {
		return nil, err
	}
	sh := &labShell{c: c, prompts: []string{l.p.node + "#", l.p.node + ">"}}
	if _, err := c.expect(60*time.Second, sh.prompts...); err != nil {
		c.Close()
		return nil, err
	}
	paging := "terminal length 0"
	if strings.HasPrefix(l.p.name, "juniper_") {
		paging = "set cli screen-length 0"
	}
	if _, err := c.sendExpect(paging, 30*time.Second, sh.prompts...); err != nil {
		c.Close()
		return nil, err
	}
	return sh, nil
}

// Run sends cmd and waits up to per for the prompt: its output, how long,
// and the error at the deadline, which a caller reads as "not observed".
func (sh *labShell) Run(cmd string, per time.Duration) (string, time.Duration, error) {
	return sh.runUntil(cmd, per)
}

// runUntil is Run that also stops at any of also: a `[confirm]`, or a
// configuration prompt, which ptyCommands answers.
func (sh *labShell) runUntil(cmd string, per time.Duration, also ...string) (string, time.Duration, error) {
	t0 := time.Now()
	out, err := sh.c.sendExpect(cmd, per, append(also, sh.prompts...)...)
	return out, time.Since(t0), err
}

func (sh *labShell) Close() { sh.c.Close() }

// singleConnection turns the platform's TACACS+ single-connection mode on
// where the image offers it — asked at `?` first, on every platform, so the
// image, not this code, decides (conflict scan F15) — and says what it did.
// Both the question and the change go over a break-glass CLI with port49d
// stopped (withAdminCLI), which restarts it on the standing config: a caller
// that wants another config restarts port49d on it afterwards.
//
// Junos is asked in two places: its accounting has a server stanza of its
// own (`system accounting destination tacplus server`), and accounting is
// what an open Junos session sends port49, since Junos authorizes commands
// locally by class. Each place is set only where its own `?` offered it.
func (l *lab) singleConnection(t *testing.T) string {
	t.Helper()
	places := singleConnectionPlaces(l.p.name)
	var set, said []string
	for _, p := range places {
		ok, help := l.offered(t, p.enter, p.ask, "single-connection")
		if !ok {
			said = append(said, fmt.Sprintf("not available at `%s`: after `%s`, its `?` did not offer "+
				"single-connection; the device said:\n\n```\n%s\n```\n", strings.Join(p.ask, "`, `"),
				strings.Join(p.enter, "`, `"), strings.TrimSpace(strings.ReplaceAll(help, "\r", ""))))
			continue
		}
		set = append(set, p.lines...)
		said = append(said, "on: "+p.said)
	}
	switch {
	case len(set) == 0:
		return strings.Join(said, "; ") + "\nThe phases run on whatever connections the device opens"
	case strings.HasPrefix(l.p.name, "juniper_"):
		l.junosConfigureAdmin(t, set)
	default:
		l.carriedConfigure(t, set...)
	}
	return strings.Join(said, "; ")
}

// scPlace is one place singleConnection asks for the mode and sets it.
type scPlace struct {
	enter, ask []string // configuration mode, then the context the keyword is asked in
	lines      []string // what sets it, typed in configuration mode
	said       string
}

// singleConnectionPlaces is where platform is asked for single-connection and
// the lines that set it. EOS takes the keyword before `key` (its run on
// 2026-09-30 set it so). NX-OS takes nothing after `single-connection` and
// takes it after `key 0 <key>`: its `?` after `single-connection` offers only
// <CR>, and after `key 0 <key>` offers single-connection
// (tests/lab/results/single-connection-syntax-cisco_nxos.md).
func singleConnectionPlaces(platform string) []scPlace {
	switch {
	case strings.HasPrefix(platform, "juniper_"):
		var places []scPlace
		for _, ctx := range []string{"set system tacplus-server 172.100.100.1",
			"set system accounting destination tacplus server 172.100.100.1"} {
			places = append(places, scPlace{enter: []string{"configure"}, ask: []string{ctx + " ?"},
				lines: []string{ctx + " single-connection"}, said: "`" + ctx + " single-connection`"})
		}
		return places
	case platform == "cisco_iosxe":
		return []scPlace{{enter: []string{"configure terminal", "tacacs server port49-host"}, ask: []string{"?"},
			lines: []string{"tacacs server port49-host", "single-connection"},
			said:  "`single-connection` under `tacacs server port49-host`"}}
	case platform == "cisco_nxos":
		return []scPlace{{enter: []string{"configure terminal"}, ask: []string{"tacacs-server host 172.100.100.1 ?"},
			lines: []string{"tacacs-server host 172.100.100.1 key 0 " + labKeyDefault + " single-connection"},
			said:  "`tacacs-server host 172.100.100.1 key 0 <key> single-connection`"}}
	}
	return []scPlace{{enter: []string{"configure terminal"}, ask: []string{"tacacs-server host 172.100.100.1 ?"},
		lines: []string{"tacacs-server host 172.100.100.1 single-connection key 0 " + labKeyDefault},
		said:  "`tacacs-server host 172.100.100.1 single-connection`"}}
}

// offered asks the device, as break-glass in configuration mode, for the
// help at the end of ask, and reports whether keyword is among the choices,
// with the help the device printed. Each ask is typed without a newline:
// `?` is answered as it is typed, and a newline after it would submit the
// half line. The half line is then cleared (Ctrl-U) and configuration mode
// left without committing anything.
func (l *lab) offered(t *testing.T, enter, ask []string, keyword string) (bool, string) {
	t.Helper()
	open, leave, back := adminCLI, "end", l.p.node+"#"
	if strings.HasPrefix(l.p.name, "juniper_") {
		open = func(l *lab) (*cliConn, error) { return l.junosCLI(breakglassUser, breakglassPassword) }
		leave, back = "exit configuration-mode", junosOpPrompt
	}
	cfg := []string{l.p.node + "(config", l.p.node + "#", l.p.node + ">"}
	var help string
	// An ask may carry the lab key (TestSingleConnectionSyntax types it to
	// read the help after it): every error and the help returned have it
	// replaced by <key>, so a failure prints no key.
	redact := func(s string) string { return strings.ReplaceAll(s, labKeyDefault, "<key>") }
	l.withAdminCLI(t, open, func(c *cliConn) error {
		if err := l.offeredIn(c, enter, ask, cfg, leave, back, &help); err != nil {
			return errors.New(redact(err.Error()))
		}
		return nil
	})
	help = redact(help)
	return strings.Contains(help, keyword), help
}

// offeredIn is offered's work on an open admin CLI c: enter, each ask and its
// help appended to help, Ctrl-U, and leave.
func (l *lab) offeredIn(c *cliConn, enter, ask, cfg []string, leave, back string, help *string) error {
	for _, e := range enter {
		if _, err := c.sendExpect(e, 30*time.Second, cfg...); err != nil {
			return fmt.Errorf("the `?` check: %s: %w", e, err)
		}
	}
	for _, a := range ask {
		from := len(c.transcript())
		if _, err := fmt.Fprint(c.in, a); err != nil {
			return fmt.Errorf("the `?` check: %s: %w", a, err)
		}
		// The help ends with the prompt and the half line redrawn.
		out, err := c.expectFrom(from, 30*time.Second, cfg...)
		if err != nil {
			return fmt.Errorf("the `?` check: %s: the help was not observed: %w", a, err)
		}
		*help += out
	}
	if _, err := fmt.Fprint(c.in, "\x15"); err != nil { // Ctrl-U: clear what `?` left on the line
		return err
	}
	if _, err := c.sendExpect(leave, 30*time.Second, back); err != nil {
		return fmt.Errorf("the `?` check: %s: %w", leave, err)
	}
	return nil
}

// timedLogins is a token login, and a break-glass login with three `show
// version`, each timed as l28Phase times them, as two table rows.
func (l *lab) timedLogins(t *testing.T) string {
	t.Helper()
	rows, _, _, _ := l.timeLogins(t)
	return rows
}

// timeLogins is timedLogins plus when the break-glass session began, how long
// it took, and whether it logged in and ran its commands, for a test that
// holds it to a bar and reads the capture over its interval (L31).
func (l *lab) timeLogins(t *testing.T) (rows string, bgFrom time.Time, bgTook time.Duration, bgOK bool) {
	t.Helper()
	user, secret := l.nextLogin(t)
	t0 := time.Now()
	tok := "logged in"
	if c, err := l.dial(user, secret, 120*time.Second); err != nil {
		tok = "refused: " + oneLine(err.Error())
	} else {
		c.Close()
	}
	tokTook := time.Since(t0)
	bgFrom = time.Now()
	outs, err := l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version", "show version",
		"show version")
	bgTook = time.Since(bgFrom)
	bg, bgOK := breakglassRan(l.p.name, outs, err, 3)
	return fmt.Sprintf("| next token login (`%s`) | %s in %s |\n| break-glass login plus three `show version` | %s in %s |\n",
		user, tok, tokTook.Round(10*time.Millisecond), bg, bgTook.Round(10*time.Millisecond)), bgFrom, bgTook, bgOK
}

// breakglassRan reads a break-glass session's outputs: it ran its commands
// only if it logged in, every one of the want commands answered, and none
// answered with platform's refusal text (l29Refusals). A session that logged
// in and was refused every command is not one that ran them.
func breakglassRan(platform string, outs []string, err error, want int) (string, bool) {
	if err != nil {
		return "not observed: " + oneLine(err.Error()), false
	}
	for _, out := range outs {
		if l29Refused(platform, out) {
			for _, line := range strings.Split(out, "\n") {
				if l29Refused(platform, line) {
					return "refused: " + oneLine(line), false
				}
			}
		}
	}
	if len(outs) != want {
		return fmt.Sprintf("ran %d of %d", len(outs), want), false
	}
	return "logged in and ran them", true
}

// firstLine is s's first non-empty line, for a table cell.
func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(line)
}
