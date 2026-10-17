//go:build lab

package lab

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const l71Claim = "Whether this image's CLI offers an RFC 9887 (TACACS+ over TLS) client, read from the CLI's own " +
	"help with nothing left configured (on IOS-XE the probe creates a `tacacs server l71probe` object and removes " +
	"it) (policy engine spec §15 L71; §13 decision 50 ruling 19). Vendor " +
	"documentation puts the floor at Arista EOS 4.36.1F, Cisco IOS XE 17.18.1, Cisco NX-OS 10.6(1)F and Junos " +
	"26.2R1 on routing and switching platforms, not SRX; every lab image predates them. L71 probes only the images in the harness platform list: vJunosEvolved " +
	"23.4R2-S2.1 and vSRX 23.4R1.9 are not probed."

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
		var obs, xchg strings.Builder
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
			// snap's text stays inside this function; only equality and
			// line counts leave it.
			before, err := snap()
			if err != nil {
				return l71Wrap("INVALID: reading the TACACS+ configuration before the probe", err)
			}
			// The cleanup runs on every path, an error's included: an entered
			// line may already have configured something (IOS-XE's server
			// object), and a probe that returns early must not leave it.
			entered, dirty := 0, false
			// An INVALID probe leaves its masked exchange in the workspace
			// named by PORT49_L71_INVALID_DIR (never committed), so the
			// fault can be read.
			defer func() {
				dir := os.Getenv("PORT49_L71_INVALID_DIR")
				if err == nil || dir == "" || xchg.Len() == 0 {
					return
				}
				p := filepath.Join(dir, "l71-invalid-"+l.p.name+".txt")
				if werr := os.WriteFile(p, []byte(xchg.String()), 0o644); werr != nil {
					t.Logf("could not write %s: %v", p, werr)
				}
			}()
			defer func() {
				if dirty {
					// Ctrl-U did not clear the line, so anything typed now
					// would be appended to it. The session is closed
					// instead, which discards the line unexecuted.
					return
				}
				lines := l71CleanupFor(probe, entered)
				for i, line := range lines {
					mark := probe.cfgMark
					if i == len(lines)-1 {
						mark = opMark
					}
					if _, cerr := c.sendExpect(line, 20*time.Second, mark); cerr != nil && err == nil {
						err = l71Wrap(fmt.Sprintf("cleanup %q", line), cerr)
					}
				}
				after, aerr := snap()
				switch {
				case aerr != nil:
					if err == nil {
						err = l71Wrap("reading the TACACS+ configuration after the probe", aerr)
					}
				case after != before:
					// Counts only: the text may hold key hashes.
					mismatch := fmt.Errorf("the probe changed the TACACS+ configuration (%d lines before, %d after); "+
						"inspect the device by hand, no note is written", strings.Count(before, "\n"), strings.Count(after, "\n"))
					if err != nil {
						mismatch = fmt.Errorf("%w; also: %v", err, mismatch)
					}
					err = mismatch
				}
			}()
			for _, line := range probe.enter {
				entered++ // counted when sent: a line whose reply never came may still have run
				if _, err := c.sendExpect(line, 20*time.Second, probe.cfgMark); err != nil {
					return l71Wrap(fmt.Sprintf("INVALID: %q", line), err)
				}
			}
			for _, ask := range probe.ask {
				from := len(c.transcript())
				if _, err := c.in.Write([]byte(ask + "?")); err != nil {
					return err
				}
				// The prompt is already on screen when the help is requested,
				// so a prompt cannot say the help has printed. A control
				// option says it has started, and the configuration prompt
				// redisplayed after that option says it has finished; a help
				// that shows no control option is INVALID.
				tail, werr := c.expectFrom(from, 20*time.Second, probe.control...)
				if werr == nil {
					at := len(tail)
					for _, w := range probe.control {
						if i := strings.Index(tail, w); i >= 0 && i < at {
							at = i
						}
					}
					_, werr = c.expectFrom(from+at, 20*time.Second, probe.cfgMark)
				}
				help := strings.ReplaceAll(c.transcript()[from:], "\r", "")
				if _, uerr := c.in.Write([]byte{0x15}); uerr != nil { // Ctrl-U: the typed line is dropped, never entered
					return uerr
				}
				empty := l71WaitEmptyLine(c, 5*time.Second)
				fmt.Fprintf(&xchg, "### typed `%s?`, then Ctrl-U\n%s\n\n", ask, l71MaskExchange(c.transcript()[from:]))
				if !empty {
					dirty = true
					return fmt.Errorf("INVALID: after Ctrl-U the prompt did not return with an empty line on `%s?`; "+
						"nothing more was typed and the session was closed; on IOS-XE check for a "+
						"`tacacs server l71probe` object and on every platform for an unfinished probe line", ask)
				}
				if werr != nil {
					return l71Wrap(fmt.Sprintf("INVALID: no help for `%s?`", ask), werr)
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
		// L71 sends no TACACS+ traffic, so its capture is the CLI exchange.
		ev := filepath.Join("tests", "lab", "evidence", "L71-"+l.p.name)
		if err := os.MkdirAll(filepath.Join(root, ev), 0o755); err != nil {
			t.Fatalf("evidence directory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, ev, "probe.txt"), []byte(xchg.String()), 0o644); err != nil {
			t.Fatalf("write probe.txt: %v", err)
		}
		l.captureNote = fmt.Sprintf("`%s/probe.txt` — the CLI exchange from the help request to the empty-line check, "+
			"credentials masked and control bytes shown as `cat -v` shows them. L71 sends no TACACS+ traffic, so there is no pcap.", ev)
		l.result(t, "L71", l71Claim, obs.String())
	})
}

// l71WaitEmptyLine waits up to within for the CLI's last line to be a bare
// prompt, as it is once Ctrl-U has cleared what was typed.
func l71WaitEmptyLine(c *cliConn, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for {
		if l71LineEmpty(c.transcript()) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(250 * time.Millisecond)
	}
}
