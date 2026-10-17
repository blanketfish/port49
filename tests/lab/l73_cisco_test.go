//go:build lab

package lab

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// l73Opener is the platform's break-glass CLI, the opener withAdminCLI
// takes (adminCLI covers neither Junos nor the help-only rows).
func l73Opener(name string) func(*lab) (*cliConn, error) {
	switch name {
	case "juniper_vjunos-router", "juniper_vjunos-switch":
		return func(l *lab) (*cliConn, error) { return l.junosCLI(breakglassUser, breakglassPassword) }
	case "cisco_iosxe":
		return func(l *lab) (*cliConn, error) { return l.iosxeCLI(breakglassUser, breakglassPassword) }
	case "cisco_nxos":
		return func(l *lab) (*cliConn, error) { return l.nxosCLI(breakglassUser, breakglassPassword) }
	case "arista_ceos":
		return func(l *lab) (*cliConn, error) { return l.eosCLI(breakglassUser, breakglassPassword) }
	case "cisco_iol-xe":
		// No console fallback: containerlab runs IOL directly, not as a
		// vrnetlab VM with a serial console behind it.
		return func(l *lab) (*cliConn, error) {
			return l.iosxeCLIRaising(breakglassUser, breakglassPassword, true, false)
		}
	case "cisco_xrd":
		return func(l *lab) (*cliConn, error) { return l.xrCLI(breakglassUser, breakglassPassword) }
	}
	return nil
}

// xrCLI is an IOS XR exec CLI over SSH, paging off. XR's prompt is
// `RP/0/RP0/CPU0:xrd1#`; the node name and `#` are what is waited for, as
// on EOS.
func (l *lab) xrCLI(user, password string) (*cliConn, error) {
	c, err := l.sshCLI(user, password)
	if err != nil {
		return nil, err
	}
	c.prompt = l.p.node + "#"
	if _, err := c.expect(60*time.Second, c.prompt); err != nil {
		c.Close()
		return nil, err
	}
	if _, err := c.sendExpect("terminal length 0", 45*time.Second, c.prompt); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// l73CiscoRun types items in configuration mode, answers each item's
// questions from its steps, and returns what the device said. It waits for
// `<node>(`, which every IOS XE, NX-OS and EOS configuration prompt holds
// (`xe1(config-server-tacacs)#`, `xe1(ca-trustpoint)#`, `nx1(config)#`,
// `leaf1(config-mgmt-sec-ssl-profile-l73-tls)#`),
// where iosxeConfigure and nxosConfigure wait for `(config)#` alone and
// would hang in a submode. A refused line ends the run with an error,
// unless lenient: then it keeps going and returns every refusal together
// (the cleanup's restore, which undoes lines that may never have been
// applied). Errors name lines through hideKeys.
func l73CiscoRun(c *cliConn, items []l73Dialog, vals map[string]string, lenient bool) (out string, err error) {
	// What leaves this function is masked at the source: the device echoes
	// each typed line, and a refusal line may quote a key.
	defer func() {
		out = hideKeys(out)
		if err != nil {
			err = errors.New(hideKeys(err.Error()))
		}
	}()
	from := len(c.transcript())
	mark := strings.TrimSuffix(c.prompt, "#") + "("
	if _, err := c.sendExpect("configure terminal", 45*time.Second, mark); err != nil {
		return c.transcript()[from:], err
	}
	var refused []string
	for _, it := range items {
		at := len(c.transcript())
		if err := c.send(it.Cmd); err != nil {
			return c.transcript()[from:], err
		}
		used, pos := make([]bool, len(it.Steps)), at
		for {
			step, ok := -1, false
			for deadline := time.Now().Add(180 * time.Second); ; time.Sleep(250 * time.Millisecond) {
				if step, ok = l73NextAnswer(c.transcript()[pos:], it.Steps, used, mark); ok || time.Now().After(deadline) {
					break
				}
			}
			if !ok {
				return c.transcript()[from:], fmt.Errorf("%q: neither the configuration prompt nor a question this "+
					"dialogue knows within 180s", hideKeys(it.Cmd))
			}
			if step < 0 {
				break
			}
			used[step], pos = true, len(c.transcript())
			for _, ln := range strings.Split(l73Expand(it.Steps[step].Reply, vals), "\n") {
				if err := c.send(ln); err != nil {
					return c.transcript()[from:], err
				}
			}
		}
		said := c.transcript()[at:]
		if r := l73Refusal(said); r != "" {
			if !lenient {
				return c.transcript()[from:], fmt.Errorf("%q was refused: %s", hideKeys(it.Cmd), hideKeys(r))
			}
			refused = append(refused, hideKeys(it.Cmd)+": "+hideKeys(r))
		} else if it.Done != "" && !strings.Contains(said, it.Done) {
			return c.transcript()[from:], fmt.Errorf("%q: the device never said %q", hideKeys(it.Cmd), it.Done)
		}
	}
	if _, err := c.sendExpect("end", 45*time.Second, c.prompt); err != nil {
		return c.transcript()[from:], err
	}
	if len(refused) > 0 {
		return c.transcript()[from:], fmt.Errorf("refused: %s", strings.Join(refused, "; "))
	}
	return c.transcript()[from:], nil
}
