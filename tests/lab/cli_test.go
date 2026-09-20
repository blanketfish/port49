//go:build lab

package lab

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// A cliConn is an interactive session with a device's own command line, used by
// the tests that have to *change* the device's configuration mid-run rather
// than only log in to it.
//
// L4 is why this exists. Its matrix is two authentication orders crossed with
// two server conditions, and re-deploying per cell would cost four VM boots per
// platform on a budget of five. So the order is switched in place: log in,
// commit the change, measure, change it back.
//
// Two transports, one interface. SSH is the normal one. The console is the
// fallback, and it is not hypothetical: the whole point of L4 is that a device
// may refuse every login when TACACS+ says no, and on such a device SSH is
// exactly the channel that is unavailable when the order needs changing back.
type cliConn struct {
	name   string // how the results note should describe this channel
	prompt string // the device's idle prompt, once it is known
	in     io.Writer
	out    *syncBuf
	close  func()
}

// syncBuf collects device output. The ssh package writes to it from its own
// goroutine while expect reads, so it is locked.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// Close closes the channel. Safe to call twice.
func (c *cliConn) Close() {
	if c.close != nil {
		c.close()
		c.close = nil
	}
}

func (c *cliConn) send(line string) error {
	_, err := fmt.Fprintf(c.in, "%s\n", line)
	return err
}

// expectFrom waits for any of want to appear in what the device has said since
// offset from, and returns that tail either way.
//
// The offset is the whole point. Matching against the entire transcript looks
// simpler and is wrong: a prompt matcher like `> ` is satisfied by the *first*
// prompt for the rest of the session, so every later command returns instantly
// and the test measures a device that has not answered yet.
func (c *cliConn) expectFrom(from int, within time.Duration, want ...string) (string, error) {
	deadline := time.Now().Add(within)
	for {
		s := c.out.String()
		if from > len(s) {
			from = len(s)
		}
		tail := s[from:]
		for _, w := range want {
			if strings.Contains(tail, w) {
				return tail, nil
			}
		}
		if !time.Now().Before(deadline) {
			return tail, fmt.Errorf("none of %q appeared on the %s within %v; what it said was:\n%s",
				want, c.name, within, tail)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// expect waits for any of want anywhere in the transcript. Only the opening
// banner uses it, where there is nothing before to confuse it with.
func (c *cliConn) expect(within time.Duration, want ...string) (string, error) {
	return c.expectFrom(0, within, want...)
}

// sendExpect sends one line and waits for one of want in the output that
// follows it.
func (c *cliConn) sendExpect(line string, within time.Duration, want ...string) (string, error) {
	from := len(c.out.String())
	if err := c.send(line); err != nil {
		return c.out.String(), err
	}
	return c.expectFrom(from, within, want...)
}

// transcript is everything the device has said on this channel.
func (c *cliConn) transcript() string { return c.out.String() }

// sshCLI opens an interactive shell over SSH with a pty. A pty is what makes
// the device run its own CLI rather than a one-shot command interpreter, which
// is what a configuration change needs on Junos.
func (l *lab) sshCLI(user, password string) (*cliConn, error) {
	c, err := l.dial(user, password, 60*time.Second)
	if err != nil {
		return nil, err
	}
	s, err := c.NewSession()
	if err != nil {
		c.Close()
		return nil, err
	}
	if err := s.RequestPty("vt100", 200, 200, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		s.Close()
		c.Close()
		return nil, fmt.Errorf("request pty: %w", err)
	}
	in, err := s.StdinPipe()
	if err != nil {
		s.Close()
		c.Close()
		return nil, err
	}
	buf := &syncBuf{}
	s.Stdout, s.Stderr = buf, buf
	if err := s.Shell(); err != nil {
		s.Close()
		c.Close()
		return nil, fmt.Errorf("start shell: %w", err)
	}
	return &cliConn{
		name: "SSH CLI as " + user,
		in:   in,
		out:  buf,
		close: func() {
			in.Close()
			go s.Wait()
			s.Close()
			c.Close()
		},
	}, nil
}

// consoleCLI opens the VM's serial console. vrnetlab runs qemu with the guest
// serial port on telnet 5000 inside the container, and the management address
// is routable from the host, so the console is one dial away.
//
// It is the channel of last resort and it is here on purpose: a device that
// refuses SSH for every account — which is one of the outcomes L4 exists to
// measure — still answers here, and putting its configuration back afterwards
// would otherwise need a redeploy.
func (l *lab) consoleCLI() (*cliConn, error) {
	nc, err := net.DialTimeout("tcp", l.p.addr+":5000", 15*time.Second)
	if err != nil {
		return nil, fmt.Errorf("serial console %s:5000: %w", l.p.addr, err)
	}
	buf := &syncBuf{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		telnetPump(nc, buf)
	}()
	c := &cliConn{
		name: "serial console (" + l.p.addr + ":5000)",
		in:   nc,
		out:  buf,
		close: func() {
			nc.Close()
			<-done
		},
	}
	// A console that has been sitting idle shows nothing until something is
	// typed. A bare newline is the cheapest way to make it say where it is.
	_ = c.send("")
	return c, nil
}

// telnetPump copies the console to buf, answering telnet option negotiation
// along the way. qemu's telnet server opens with a handful of DO/WILL commands;
// left unanswered they are harmless, but the IAC bytes themselves would land in
// the transcript and break a literal match on whatever the device said next.
func telnetPump(c net.Conn, buf *syncBuf) {
	const (
		iac  = 255
		dont = 254
		do   = 253
		wont = 252
		will = 251
		sb   = 250
		se   = 240
	)
	r := make([]byte, 4096)
	var pend []byte
	for {
		n, err := c.Read(r)
		if n > 0 {
			pend = append(pend, r[:n]...)
			var out []byte
			i := 0
			for i < len(pend) {
				if pend[i] != iac {
					out = append(out, pend[i])
					i++
					continue
				}
				if i+1 >= len(pend) {
					break // wait for the rest of the command
				}
				switch cmd := pend[i+1]; cmd {
				case do, dont, will, wont:
					if i+2 >= len(pend) {
						i = len(pend) // incomplete; drop, the option is not load-bearing
						break
					}
					// Refuse everything: this is a raw serial console, and the
					// only thing negotiation could do here is confuse it.
					reply := byte(dont)
					if cmd == do || cmd == dont {
						reply = wont
					}
					_, _ = c.Write([]byte{iac, reply, pend[i+2]})
					i += 3
				case sb:
					// Skip to IAC SE.
					j := i + 2
					for j+1 < len(pend) && !(pend[j] == iac && pend[j+1] == se) {
						j++
					}
					if j+1 >= len(pend) {
						i = len(pend)
						break
					}
					i = j + 2
				case iac:
					out = append(out, iac)
					i += 2
				default:
					i += 2
				}
			}
			if i >= len(pend) {
				pend = nil
			} else {
				pend = append([]byte(nil), pend[i:]...)
			}
			if len(out) > 0 {
				buf.Write(out)
			}
		}
		if err != nil {
			return
		}
	}
}

// junosCLI returns a Junos operational-mode CLI, over SSH as user if that works
// and over the serial console as root if it does not. cliConn.name says which,
// so a results note can report the channel it was read over.
//
// Console login on these images is root with no password, which is how the
// vSRX configuration was read in results/juniper_vsrx-config-verified.md.
func (l *lab) junosCLI(user, password string) (*cliConn, error) {
	c, sshErr := l.sshCLI(user, password)
	if sshErr == nil {
		if _, err := c.expect(60*time.Second, junosOpPrompt, "% "); err != nil {
			c.Close()
			return nil, err
		}
		if err := junosPrepare(c); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}
	c, err := l.consoleCLI()
	if err != nil {
		return nil, fmt.Errorf("SSH CLI failed (%v) and the console did not open either: %w", sshErr, err)
	}
	c.name += " as root, after SSH as " + user + " failed (" + sshErr.Error() + ")"
	out, err := c.sendExpect("", 90*time.Second, "login:", junosOpPrompt, "% ")
	if err != nil {
		c.Close()
		return nil, err
	}
	if strings.Contains(out, "login:") {
		if out, err = c.sendExpect("root", 90*time.Second, "% ", junosOpPrompt, "assword"); err != nil {
			c.Close()
			return nil, err
		}
		if strings.Contains(out, "assword") {
			// root has no password on these images, but the console asks anyway
			// on some of them. An empty line answers it; if the device is in a
			// state where root does have one, the only credential this lab knows
			// is the break-glass password, so try that before giving up.
			if out, err = c.sendExpect("", 90*time.Second, "% ", junosOpPrompt, "incorrect", "login:"); err != nil {
				c.Close()
				return nil, err
			}
			if !strings.Contains(out, "% ") && !strings.Contains(out, junosOpPrompt) {
				if _, err = c.sendExpect(breakglassUser, 60*time.Second, "assword"); err != nil {
					c.Close()
					return nil, err
				}
				if out, err = c.sendExpect(breakglassPassword, 90*time.Second, "% ", junosOpPrompt, "incorrect"); err != nil {
					c.Close()
					return nil, err
				}
				if strings.Contains(out, "incorrect") {
					c.Close()
					return nil, fmt.Errorf("the console refused both root with no password and %s", breakglassUser)
				}
			}
		}
	}
	// A FreeBSD shell prompt means the CLI has not been entered yet.
	if !strings.Contains(out, junosOpPrompt) {
		if _, err := c.sendExpect("cli", 90*time.Second, junosOpPrompt); err != nil {
			c.Close()
			return nil, err
		}
	}
	if err := junosPrepare(c); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// The prompts these helpers wait for. The trailing space matters: `#` alone
// appears inside plenty of device output, `# ` at a prompt does not.
// The prompts these helpers wait for. On Junos the trailing space matters: `#`
// alone appears inside plenty of device output, `# ` at a prompt does not. EOS
// prints no trailing space at all — its prompt is exactly `leaf1#` — so there
// the node name is the only thing specific enough to wait for, and cliConn
// carries it.
const (
	junosOpPrompt  = "> "
	junosCfgPrompt = "# "
	eosCfgPrompt   = "(config)#"
)

// junosPrepare turns off paging, so a `show` command does not stop at a
// `---(more)---` prompt that expect would wait out in full.
func junosPrepare(c *cliConn) error {
	_, err := c.sendExpect("set cli screen-length 0", 45*time.Second, junosOpPrompt)
	return err
}

// junosConfigure enters configuration mode, applies lines, and commits. It
// returns the commit output, and an error unless the device said the commit
// completed — a commit that failed silently would leave every later cell of the
// matrix measuring the previous configuration.
func junosConfigure(c *cliConn, lines ...string) (string, error) {
	if _, err := c.sendExpect("configure", 60*time.Second, junosCfgPrompt); err != nil {
		return c.transcript(), fmt.Errorf("entering configuration mode: %w", err)
	}
	for _, ln := range lines {
		out, err := c.sendExpect(ln, 60*time.Second, junosCfgPrompt)
		if err != nil {
			return out, fmt.Errorf("%q: %w", ln, err)
		}
		if strings.Contains(out, "syntax error") || strings.Contains(out, "unknown command") {
			return out, fmt.Errorf("%q was refused by the device:\n%s", ln, out)
		}
	}
	out, err := c.sendExpect("commit", 180*time.Second, "commit complete", "error:", "failed")
	if err != nil {
		return out, fmt.Errorf("commit: %w", err)
	}
	if !strings.Contains(out, "commit complete") {
		return out, fmt.Errorf("the commit did not complete:\n%s", out)
	}
	if _, err := c.sendExpect("exit", 60*time.Second, junosOpPrompt); err != nil {
		return out, fmt.Errorf("leaving configuration mode: %w", err)
	}
	return out, nil
}

// junosShow runs one operational-mode command and returns just its output.
func junosShow(c *cliConn, cmd string) (string, error) {
	return c.sendExpect(cmd, 60*time.Second, junosOpPrompt)
}

// eosCLI returns an EOS enable-mode CLI over SSH, with paging off.
func (l *lab) eosCLI(user, password string) (*cliConn, error) {
	c, err := l.sshCLI(user, password)
	if err != nil {
		return nil, err
	}
	c.prompt = l.p.node + "#"
	if _, err := c.expect(45*time.Second, l.p.node+">", c.prompt); err != nil {
		c.Close()
		return nil, err
	}
	if _, err := c.sendExpect("enable", 45*time.Second, c.prompt, "assword"); err != nil {
		c.Close()
		return nil, err
	}
	if _, err := c.sendExpect("terminal length 0", 45*time.Second, c.prompt); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// eosConfigure applies configuration lines on EOS. There is no commit; a line
// the parser rejects answers with `% Invalid input`, which is checked for
// because a silently ignored line would leave the next cell measuring the old
// method list.
func eosConfigure(c *cliConn, lines ...string) (string, error) {
	from := len(c.transcript())
	if _, err := c.sendExpect("configure", 45*time.Second, eosCfgPrompt); err != nil {
		return c.transcript(), err
	}
	for _, ln := range lines {
		out, err := c.sendExpect(ln, 45*time.Second, eosCfgPrompt)
		if err != nil {
			return out, fmt.Errorf("%q: %w", ln, err)
		}
		if strings.Contains(out, "% Invalid input") || strings.Contains(out, "% Incomplete") {
			return out, fmt.Errorf("%q was refused by the device:\n%s", ln, out)
		}
	}
	if _, err := c.sendExpect("end", 45*time.Second, c.prompt); err != nil {
		return c.transcript(), err
	}
	return c.transcript()[from:], nil
}

// eosShow runs one command and returns just its output.
func eosShow(c *cliConn, cmd string) (string, error) {
	return c.sendExpect(cmd, 60*time.Second, c.prompt)
}
