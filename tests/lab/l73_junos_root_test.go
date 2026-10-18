//go:build lab

package lab

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// l73HostCA is one public CA certificate and the two names openssl gives its
// subject on the host.
type l73HostCA struct {
	Src         string
	Cur, OldHsh string
}

// l73RootJob is what one root-shell session does. SetHash sets the root
// password's hash first (the first session only). Group and CAs fill the trust
// folder. ClientNode makes the client key and request in the certificate-id
// folder (the key never leaves it) and fetches the request; PlaceClient puts
// the signed certificate beside the key.
type l73RootJob struct {
	SetHash     bool
	Group       string
	CAs         []l73HostCA
	ClientNode  string
	PlaceClient bool
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
	ClientMade     bool
	ClientCSR      string // the request, public, as the CLI showed it
	ClientListing  string
	OpenSSLVersion string
	ClientKey      string // which command made the key
	OpenSSLHelp    string
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
func l73JunosRoot(c *cliConn, job l73RootJob, pw, hash string) (l73RootOutcome, string, error) {
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
	if job.SetHash {
		if out, err := junosConfigure(c, `set system root-authentication encrypted-password "`+hash+`"`); err != nil {
			keep(out)
			return fail("the image did not take an encrypted-password for root: %v", err)
		}
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

	// Each root command is followed on the next line by `echo rc=$?`, and the
	// prompt is awaited only after that answer, so a slow command cannot race
	// the next and a command that fails without a word still fails. The
	// output is what came before the rc line.
	rcLine := regexp.MustCompile(`(?m)^rc=(\d+)\s*$`)
	shell := func(cmd string) (string, error) {
		if !l73RootCmdAllowed(cmd) {
			return "", fmt.Errorf("%q is not a line the root shell may run", cmd)
		}
		from := len(c.transcript())
		if err := c.send(cmd); err != nil {
			return "", err
		}
		if err := c.send("echo rc=$?"); err != nil {
			return "", err
		}
		var tail string
		deadline := time.Now().Add(120 * time.Second)
		for {
			tail = c.transcript()[from:]
			if rcLine.MatchString(tail) || time.Now().After(deadline) {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		m := rcLine.FindStringSubmatchIndex(tail)
		if m == nil {
			screen.WriteString("$ " + cmd + "\n")
			keep(tail)
			return tail, fmt.Errorf("%q: no exit status came back", cmd)
		}
		out := l73ShellBody(strings.ReplaceAll(tail[:m[0]], "\r", ""), cmd)
		rc := tail[m[2]:m[3]]
		if _, err := c.expectFrom(from+m[1], 60*time.Second, "# ", "% "); err != nil {
			return out, fmt.Errorf("%q: the prompt did not return: %v", cmd, err)
		}
		fail := func(why string) (string, error) {
			screen.WriteString("$ " + cmd + "\n")
			keep(out)
			return out, fmt.Errorf("%q: %s", cmd, why)
		}
		if rc != "0" && cmd != "which openssl" && cmd != "openssl help" {
			return fail("exit status rc=" + rc)
		}
		low := strings.ToLower(out)
		for _, bad := range []string{"permission denied", "no such file", "cannot", "not found", "usage:", "error"} {
			if cmd != "which openssl" && cmd != "openssl help" && strings.Contains(low, bad) {
				return fail("the shell said " + strconv.Quote(bad))
			}
		}
		return out, nil
	}
	leave := func() { _, _ = c.sendExpect("exit", 60*time.Second, junosOpPrompt) }

	// The version is kept on a failure too: the screen shows what the device has.
	if v, err := shell("openssl version"); err == nil {
		o.OpenSSLVersion = oneLine(v)
		screen.WriteString("$ openssl version\n" + mask(v) + "\n")
	}
	which, err := shell("which openssl")
	if err != nil {
		leave()
		return fail("%v", err)
	}
	o.DeviceOpenSSL = l73ParseWhich(which)
	if job.ClientNode != "" && o.DeviceOpenSSL {
		// `openssl help` prints a command list (to stderr on some builds); its rc is
		// not the point, so it is neither rc- nor word-checked.
		if h, err := shell("openssl help"); err == nil || h != "" {
			o.OpenSSLHelp = h
			screen.WriteString("$ openssl help\n" + mask(h) + "\n")
		}
	}
	if job.ClientNode != "" && !o.DeviceOpenSSL {
		leave()
		return fail("the root shell has no openssl, so the client key cannot be made in place")
	}
	var certs []l73RootCert
	for _, ca := range job.CAs {
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
	var cmds []string
	if len(certs) > 0 {
		var err error
		if cmds, err = l73RootTrustCmds(job.Group, certs); err != nil {
			leave()
			return fail("%v", err)
		}
	}
	if job.PlaceClient {
		cmds = append(cmds, l73RootPlaceCmds()...)
	}
	for _, cmd := range cmds {
		got, err := shell(cmd)
		if err != nil {
			o.Withheld = len(got)
			leave()
			return fail("%v", err)
		}
		switch {
		case strings.HasPrefix(cmd, "ls -l "+l73ClientDir):
			o.ClientListing = strings.TrimSpace(mask(strings.ReplaceAll(got, "\r", "")))
		case strings.HasPrefix(cmd, "ls -l"):
			o.Listing = strings.TrimSpace(mask(strings.ReplaceAll(got, "\r", "")))
		case strings.HasPrefix(cmd, "cp ") && !strings.Contains(cmd, l73ClientCRT):
			o.Placed = append(o.Placed, cmd[strings.LastIndex(cmd, "/")+1:])
		}
	}
	if job.ClientNode != "" {
		prep, reqEC, reqRSA, finish, err := l73RootClientCmds(job.ClientNode)
		if err != nil {
			leave()
			return fail("%v", err)
		}
		run := func(cmds ...string) error {
			for _, cmd := range cmds {
				if got, err := shell(cmd); err != nil {
					o.Withheld = len(got)
					return err
				}
			}
			return nil
		}
		if !l73ListsCommand(o.OpenSSLHelp, "req") {
			leave()
			return fail("the root shell's `openssl help` does not list req, the one command left that can make a key")
		}
		if err := run(prep...); err != nil {
			leave()
			return fail("%v", err)
		}
		o.ClientKey = "EC P-256 (openssl req -newkey ec)"
		if ecErr := run(reqEC); ecErr != nil {
			o.ClientKey = "RSA 2048 (openssl req -newkey rsa:2048)"
			if rsaErr := run(reqRSA); rsaErr != nil {
				leave()
				return fail("the client key could not be made: %v; and then %v", ecErr, rsaErr)
			}
		}
		if err := run(finish...); err != nil {
			leave()
			return fail("%v", err)
		}
		o.ClientMade = true
	}
	if _, err := c.sendExpect("exit", 60*time.Second, junosOpPrompt); err != nil {
		return fail("leaving the root shell: %v", err)
	}
	if o.ClientMade {
		out, err := c.sendExpect("file show "+l73ClientCSR, 60*time.Second, junosOpPrompt)
		if err != nil {
			return fail("reading the client request: %v", err)
		}
		o.ClientCSR = out
	}
	return o, screen.String(), nil
}

// l73ShellBody is what a root command printed: the screen between the command
// and the rc line, without the echoed command lines and the prompt.
func l73ShellBody(s, cmd string) string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || strings.Contains(t, "echo rc=$?") || strings.Contains(t, cmd) || strings.HasSuffix(t, " #") || strings.HasSuffix(t, " %") || t == "#" || t == "%" {
			continue
		}
		out = append(out, t)
	}
	return strings.Join(out, "\n")
}

// Facts are the lines the results note carries about the root step.
func (o l73RootOutcome) Facts() []string {
	var facts []string
	if o.OpenSSLVersion != "" {
		facts = append(facts, "the root shell's `openssl version`: "+o.OpenSSLVersion)
	}
	if len(o.Placed) > 0 {
		set := "absent"
		if o.RootAuthWasSet {
			set = "present"
		}
		names := "both the current and the pre-1.0 subject hash (the device shell has no openssl to say which it wants)"
		if o.DeviceOpenSSL {
			names = "the subject hash, which the device's own openssl confirmed"
		}
		facts = append(facts,
			"the trust folder was filled through the root shell, lab only: root-authentication was "+set+" on the image; this run set only a hash of a random password made in the harness process and typed the password only at `start shell user root`'s Password: prompt",
			"`start shell user ?` answered: "+oneLine(o.StartShellHelp),
			"CA file names: "+names+"; placed "+strings.Join(o.Placed, ", "),
			"the folder as listed by root: "+oneLine(o.Listing))
	}
	if o.ClientMade {
		facts = append(facts, "the client key and certificate were placed in a root-owned folder through the root shell: the device's own openssl made the key in place, "+o.ClientKey+" (`"+l73ClientDir+"/client.key`, mode 600), nothing read it back or copied it, only its request left the device and the lab intermediate's signed certificate was copied beside it as `client.crt`. The names client.key and client.crt are inferred from Juniper's RADSEC page, and are measured only if the handshake shows the device's certificate")
	}
	if o.OpenSSLHelp != "" {
		facts = append(facts, "the root shell's `openssl help` lists: "+oneLine(o.OpenSSLHelp))
	}
	if o.ClientListing != "" {
		facts = append(facts, "the client folder as listed by root: "+oneLine(o.ClientListing))
	}
	return facts
}
