//go:build lab

package lab

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const l71Claim = "Whether this image's CLI offers an RFC 9887 (TACACS+ over TLS) client, read from the CLI's own " +
	"help with nothing left configured (on IOS-XE the probe creates a `tacacs server l71probe` object and removes " +
	"it) (policy engine spec §15 L71; §13 decision 50 ruling 19). Vendor " +
	"documentation puts the floor at Arista EOS 4.36.1F, Cisco IOS XE 17.18.1, Cisco NX-OS 10.6(1)F and Junos " +
	"26.2R1 on routing and switching platforms, not SRX; every lab image predates them."

// l71Settle is how long the probe lets a help listing finish printing once
// its first control word has appeared.
const l71Settle = 2 * time.Second

func TestL71TLSClientSupport(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
			t.Fatal(err)
		}
		probe, ok := l71Probes[l.p.name]
		if !ok {
			t.Fatalf("no L71 probe for %s", l.p.name)
		}
		open := map[string]func(*lab) (*cliConn, error){
			"arista_eos":            func(l *lab) (*cliConn, error) { return l.eosCLI(breakglassUser, breakglassPassword) },
			"cisco_iosxe":           func(l *lab) (*cliConn, error) { return l.iosxeCLI(breakglassUser, breakglassPassword) },
			"cisco_nxos":            func(l *lab) (*cliConn, error) { return l.nxosCLI(breakglassUser, breakglassPassword) },
			"juniper_vjunos-router": func(l *lab) (*cliConn, error) { return l.junosCLI(breakglassUser, breakglassPassword) },
			"juniper_vsrx":          func(l *lab) (*cliConn, error) { return l.junosCLI(breakglassUser, breakglassPassword) },
		}[l.p.name]
		if open == nil {
			t.Fatalf("no CLI opener for %s", l.p.name)
		}
		var obs strings.Builder
		l.withAdminCLI(t, open, func(c *cliConn) (err error) {
			opMark := probe.opMark
			if opMark == "" {
				opMark = c.prompt
			}
			// The TACACS+ configuration before the probe. Only its equality
			// is used: its text can carry key hashes and is never written.
			snap := func() (string, error) {
				out, err := c.sendExpect(probe.snapshot, 30*time.Second, opMark)
				return strings.ReplaceAll(out, "\r", ""), err
			}
			before, err := snap()
			if err != nil {
				return fmt.Errorf("INVALID: reading the TACACS+ configuration before the probe: %w", err)
			}
			// The cleanup runs on every path, an error's included: an entered
			// line may already have configured something (IOS-XE's server
			// object), and a probe that returns early must not leave it.
			defer func() {
				for i, line := range probe.cleanup {
					mark := probe.cfgMark
					if i == len(probe.cleanup)-1 {
						mark = opMark
					}
					if _, cerr := c.sendExpect(line, 20*time.Second, mark); cerr != nil && err == nil {
						err = fmt.Errorf("cleanup %q: %w", line, cerr)
					}
				}
				after, aerr := snap()
				switch {
				case aerr != nil:
					if err == nil {
						err = fmt.Errorf("reading the TACACS+ configuration after the probe: %w", aerr)
					}
				case after != before:
					// Counts only: the text may hold key hashes.
					err = fmt.Errorf("the probe changed the TACACS+ configuration (%d lines before, %d after); "+
						"inspect the device by hand, no note is written", strings.Count(before, "\n"), strings.Count(after, "\n"))
				}
			}()
			for _, line := range probe.enter {
				if _, err := c.sendExpect(line, 20*time.Second, probe.cfgMark); err != nil {
					return fmt.Errorf("INVALID: %q: %w", line, err)
				}
			}
			for _, ask := range probe.ask {
				from := len(c.transcript())
				if _, err := c.in.Write([]byte(ask + "?")); err != nil {
					return err
				}
				// The prompt is already on screen when the help is requested,
				// so a prompt cannot say the help has printed. A control
				// option can, and a help that never shows one is INVALID.
				_, werr := c.expectFrom(from, 20*time.Second, probe.control...)
				time.Sleep(l71Settle)
				help := strings.ReplaceAll(c.transcript()[from:], "\r", "")
				if _, uerr := c.in.Write([]byte{0x15}); uerr != nil { // Ctrl-U: the typed line is dropped, never entered
					return uerr
				}
				time.Sleep(500 * time.Millisecond)
				if werr != nil {
					return fmt.Errorf("INVALID: no help for `%s?`: %w", ask, werr)
				}
				line, err := l71Read(help, probe)
				if err != nil {
					return fmt.Errorf("`%s?`: %w", ask, err)
				}
				if line != "" {
					fmt.Fprintf(&obs, "**Has a client.** Typed `%s?`; the help lists:\n\n```\n%s\n```\n\nFull help:\n\n```\n%s\n```\n\n",
						ask, line, strings.TrimRight(help, "\n"))
				} else {
					obs.WriteString(negativeFinding{Claim: fmt.Sprintf("the help for `%s?` is a real option list "+
						"(it lists one of the control options %v) and lists none of %v, so this image offers no "+
						"RFC 9887 client there", ask, probe.control, probe.yes),
						Sent: ask + "?", Got: help}.render(t))
					obs.WriteString("\n")
				}
			}
			return nil
		})
		l.result(t, "L71", l71Claim, obs.String())
	})
}
