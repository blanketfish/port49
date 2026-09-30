//go:build lab

package lab

import (
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
func (l *lab) singleConnection(t *testing.T) string {
	t.Helper()
	type way struct {
		enter, ask []string // configuration mode, then the context the keyword is asked in
		set        func()
		said       string
	}
	w := way{enter: []string{"configure terminal"}, ask: []string{"tacacs-server host 172.100.100.1 ?"},
		set: func() {
			l.carriedConfigure(t, "tacacs-server host 172.100.100.1 single-connection key 0 "+labKeyDefault)
		},
		said: "`tacacs-server host 172.100.100.1 single-connection`"}
	switch {
	case strings.HasPrefix(l.p.name, "juniper_"):
		w = way{enter: []string{"configure"}, ask: []string{"set system tacplus-server 172.100.100.1 ?"},
			set: func() {
				l.junosConfigureAdmin(t, []string{"set system tacplus-server 172.100.100.1 single-connection"})
			}, said: "`set system tacplus-server 172.100.100.1 single-connection`"}
	case l.p.name == "cisco_iosxe":
		w = way{enter: []string{"configure terminal", "tacacs server port49-host"}, ask: []string{"?"},
			set:  func() { l.carriedConfigure(t, "tacacs server port49-host", "single-connection") },
			said: "`single-connection` under `tacacs server port49-host`"}
	}
	ok, help := l.offered(t, w.enter, w.ask, "single-connection")
	if !ok {
		return fmt.Sprintf("not available on this image: after `%s`, `%s` did not offer single-connection; "+
			"the device said:\n\n```\n%s\n```\n\nThe phases run on whatever connections the device opens",
			strings.Join(w.enter, "`, `"), strings.Join(w.ask, "`, `"), strings.TrimSpace(strings.ReplaceAll(help, "\r", "")))
	}
	w.set()
	return "on: " + w.said
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
	l.withAdminCLI(t, open, func(c *cliConn) error {
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
			help += out
		}
		if _, err := fmt.Fprint(c.in, "\x15"); err != nil { // Ctrl-U: clear what `?` left on the line
			return err
		}
		if _, err := c.sendExpect(leave, 30*time.Second, back); err != nil {
			return fmt.Errorf("the `?` check: %s: %w", leave, err)
		}
		return nil
	})
	return strings.Contains(help, keyword), help
}

// timedLogins is a token login, and a break-glass login with three `show
// version`, each timed as l28Phase times them, as two table rows.
func (l *lab) timedLogins(t *testing.T) string {
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
	t1 := time.Now()
	bg := "logged in and ran them"
	if _, err := l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version", "show version",
		"show version"); err != nil {
		bg = "not observed: " + oneLine(err.Error())
	}
	bgTook := time.Since(t1)
	return fmt.Sprintf("| next token login (`%s`) | %s in %s |\n| break-glass login plus three `show version` | %s in %s |\n",
		user, tok, tokTook.Round(10*time.Millisecond), bg, bgTook.Round(10*time.Millisecond))
}

// firstLine is s's first non-empty line, for a table cell.
func firstLine(s string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(s), "\n")
	return strings.TrimSpace(line)
}
