//go:build lab

package lab

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// l73HostCA is one public CA certificate and the two names openssl gives its
// subject on the host.
type l73HostCA struct {
	Src         string
	Cur, OldHsh string
}

// l73RootOutcome is what the lab-only root step learned. Every string in it
// is safe to keep: the password and its hash are masked, and the root shell's
// transcript is not kept (only the listing).
type l73RootOutcome struct {
	RootAuthWasSet bool
	StartShellHelp string
	DeviceOpenSSL  bool
	Placed         []string
	Listing        string
	Withheld       int
}

// l73JunosRoot is the lab-only root step on an open break-glass CLI, for the
// vJunos image whose trust folder only root can make.
//
// It reads whether the image already has a root-authentication (present or
// absent, nothing else), asks the CLI's help for `start shell user` and keeps
// the answer, sets the hash of the throwaway password pw (never pw), opens the
// root shell and types pw only at that shell's own Password: prompt, runs the
// l73RootCmdAllowed lines, and leaves. The second result is the scrubbed
// screen for the INVALID directory on failure. Neither it nor any error holds
// pw or the hash; the root shell's transcript is kept only as the listing.
func l73JunosRoot(c *cliConn, group string, cas []l73HostCA, pw, hash string) (l73RootOutcome, string, error) {
	var o l73RootOutcome
	var screen strings.Builder
	mask := func(s string) string { return l73MaskAll(l73ScrubLog(hideKeys(s)), pw, hash) }
	keep := func(s string) { screen.WriteString(mask(s)) }
	fail := func(format string, a ...any) (l73RootOutcome, string, error) {
		return o, screen.String(), errors.New(mask(fmt.Sprintf(format, a...)))
	}

	out, err := c.sendExpect("show configuration system root-authentication | display set", 60*time.Second, junosOpPrompt)
	if err != nil {
		keep(out)
		return fail("reading root-authentication: %v", err)
	}
	o.RootAuthWasSet = strings.Contains(out, "set system root-authentication")

	// The help is asked first and kept; the answer to `start shell user root`
	// itself decides whether this goes on.
	from := len(c.transcript())
	if _, err := c.in.Write([]byte("start shell user ?")); err != nil {
		return fail("asking help: %v", err)
	}
	help, herr := c.expectFrom(from, 20*time.Second, junosOpPrompt)
	_, _ = c.in.Write([]byte{0x15}) // Ctrl-U: the typed line is dropped, never entered
	o.StartShellHelp = strings.TrimSpace(mask(strings.ReplaceAll(help, "\r", "")))
	if herr != nil {
		keep(help)
		return fail("`start shell user ?` got no answer: %v", herr)
	}

	// Only the hash goes to the device; a refusal ends the run here.
	if out, err := junosConfigure(c, `set system root-authentication encrypted-password "`+hash+`"`); err != nil {
		keep(out)
		return fail("the image did not take an encrypted-password for root: %v", err)
	}

	from = len(c.transcript())
	if err := c.send("start shell user root"); err != nil {
		return fail("starting the shell: %v", err)
	}
	tail, err := c.expectFrom(from, 60*time.Second, "assword:", "# ", "% ", "Sorry", "denied", "not permitted")
	if err != nil {
		keep(tail)
		return fail("`start shell user root` answered neither a Password: prompt nor a shell prompt")
	}
	if strings.Contains(tail, "assword:") {
		from = len(c.transcript())
		if err := c.send(pw); err != nil {
			return fail("typing the password: %v", err)
		}
		tail, err = c.expectFrom(from, 60*time.Second, "# ", "% ", "assword:", "Sorry", "incorrect", "denied")
		if err != nil || strings.Contains(tail, "assword:") || strings.Contains(tail, "Sorry") || strings.Contains(tail, "incorrect") || strings.Contains(tail, "denied") {
			keep(tail)
			return fail("the root password was not accepted")
		}
	} else if strings.Contains(tail, "Sorry") || strings.Contains(tail, "denied") || strings.Contains(tail, "not permitted") {
		keep(tail)
		return fail("`start shell user root` was refused")
	}

	shell := func(cmd string) (string, error) {
		if !l73RootCmdAllowed(cmd) {
			return "", fmt.Errorf("%q is not a line the root shell may run", cmd)
		}
		out, err := c.sendExpect(cmd, 60*time.Second, "# ", "% ")
		if err != nil {
			return out, err
		}
		low := strings.ToLower(out)
		for _, bad := range []string{"permission denied", "no such file", "cannot", "not found", "usage:", "error"} {
			if cmd != "which openssl" && strings.Contains(low, bad) {
				return out, fmt.Errorf("%q: the shell said %q", cmd, bad)
			}
		}
		return out, nil
	}
	leave := func() { _, _ = c.sendExpect("exit", 60*time.Second, junosOpPrompt) }

	which, err := shell("which openssl")
	if err != nil {
		leave()
		return fail("%v", err)
	}
	o.DeviceOpenSSL = l73ParseWhich(which)
	var certs []l73RootCert
	for _, ca := range cas {
		if o.DeviceOpenSSL {
			cmd := "openssl x509 -noout -subject_hash -in " + ca.Src
			got, err := shell(cmd)
			if err != nil {
				leave()
				return fail("%v", err)
			}
			if h := l73ParseHash(got); h != ca.Cur {
				leave()
				return fail("the device's openssl names %s %q; the host's openssl names it %q", ca.Src, h, ca.Cur)
			}
		}
		certs = append(certs, l73RootCert{ca.Src, l73HashNames(o.DeviceOpenSSL, ca.Cur, ca.OldHsh)})
	}
	cmds, err := l73RootTrustCmds(group, certs)
	if err != nil {
		leave()
		return fail("%v", err)
	}
	for _, cmd := range cmds {
		got, err := shell(cmd)
		if err != nil {
			o.Withheld = len(got)
			leave()
			return fail("%v", err)
		}
		if strings.HasPrefix(cmd, "ls -l") {
			o.Listing = strings.TrimSpace(mask(strings.ReplaceAll(got, "\r", "")))
		}
		if strings.HasPrefix(cmd, "cp ") {
			o.Placed = append(o.Placed, cmd[strings.LastIndex(cmd, "/")+1:])
		}
	}
	if _, err := c.sendExpect("exit", 60*time.Second, junosOpPrompt); err != nil {
		return fail("leaving the root shell: %v", err)
	}
	return o, screen.String(), nil
}

// Facts are the lines the results note carries about the root step.
func (o l73RootOutcome) Facts() []string {
	set := "absent"
	if o.RootAuthWasSet {
		set = "present"
	}
	names := "both the current and the pre-1.0 subject hash (the device shell has no openssl to say which it wants)"
	if o.DeviceOpenSSL {
		names = "the subject hash, which the device's own openssl confirmed"
	}
	return []string{
		"the trust folder was filled through the root shell, lab only: root-authentication was " + set + " on the image; this run set only a hash of a random password made in the harness process and typed the password only at `start shell user root`'s Password: prompt",
		"`start shell user ?` answered: " + oneLine(o.StartShellHelp),
		"CA file names: " + names + "; placed " + strings.Join(o.Placed, ", "),
		"the folder as listed by root: " + oneLine(o.Listing),
	}
}
