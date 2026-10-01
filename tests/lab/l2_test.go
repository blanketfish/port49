//go:build lab

package lab

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// L2's truncation length (plan 7b, Task 12): `lab.deny_message_length` pads
// the lab's deny server_msg to N bytes with a counting pattern, and the
// longest prefix of it a device prints says where it cut.

const l2Claim = "Whether `server_msg` on an authorization REPLY is displayed to the operator, and at what length " +
	"it truncates."

// l2Lengths are the padded lengths, in bytes, each measured on a daemon of
// its own.
var l2Lengths = []int{64, 128, 200, 255, 256, 512, 1000}

// l2Padded is author.Lab's padLabMessage: msg, a space, and "0123456789"
// repeated, to exactly n bytes.
func l2Padded(msg string, n int) string {
	if n <= len(msg)+1 {
		return msg
	}
	var b strings.Builder
	b.WriteString(msg + " ")
	for i := 0; b.Len() < n; i++ {
		b.WriteByte('0' + byte(i%10))
	}
	return b.String()
}

// l2SessionDenial is author.Lab's deny_session server_msg, unpadded.
const l2SessionDenial = "port49: denied by lab deny_session; see 'port49 explain'"

// l2Shown is the longest prefix of msg in out, with line breaks the device
// may have inserted taken out, in bytes. A prefix shorter than l2MinShown is
// 0: "p" alone is in most of what a device prints.
func l2Shown(out, msg string) int {
	flat := strings.NewReplacer("\r", "", "\n", "").Replace(out)
	for k := len(msg); k >= l2MinShown; k-- {
		if strings.Contains(flat, msg[:k]) {
			return k
		}
	}
	return 0
}

// l2MinShown is the shortest prefix l2Shown counts: "port49: denied b",
// and lab.deny_message_length's own floor.
const l2MinShown = 16

// l2Kept is the earlier note's output-modifier observation: its "Truncation
// length" section, or, once this test has rewritten the note, the section
// it kept that in. It is read from the commit under test, so a rerun keeps
// what the committed note says, not what the last run wrote.
func l2Kept(platform string) string {
	rel := "tests/lab/results/L2-" + platform + ".md"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "git", "-C", root, "show", "HEAD:"+rel).Output()
	if err != nil {
		return ""
	}
	note := string(raw)
	if i := strings.Index(note, l2KeptHeader); i >= 0 {
		rest := note[i+len(l2KeptHeader):]
		if j := strings.Index(rest, "\nport49d, port49 and port49-inventory built"); j >= 0 {
			rest = rest[:j]
		}
		return strings.TrimSpace(rest)
	}
	if i := strings.Index(note, "### Truncation length\n"); i >= 0 {
		return strings.TrimSpace(note[i+len("### Truncation length\n"):])
	}
	return ""
}

const l2KeptHeader = "### Output modifiers (the earlier note's \"Truncation length\", kept)\n"

// l2Config is the standing config with deny_message_length, and on Junos
// deny_session, inserted under `lab:`.
func (l *lab) l2Config(n int, denySession bool) (string, error) {
	std, err := l.configPath()
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(std)
	if err != nil {
		return "", err
	}
	out := string(raw)
	i := strings.Index(out, "\nlab:\n")
	if i < 0 {
		return "", fmt.Errorf("%s has no top-level `lab:` key to put deny_message_length under", std)
	}
	at := i + len("\nlab:\n")
	ins := fmt.Sprintf("  deny_message_length: %d\n", n)
	if denySession {
		ins += "  deny_session: true\n"
	}
	out = out[:at] + ins + out[at:]
	path := filepath.Join(root, "tests", "lab", "logs", fmt.Sprintf("port49d-lab-%s-l2-%d.yaml", l.p.name, n))
	return path, os.WriteFile(path, []byte(out), 0o644)
}

// l2Restart puts port49d on cfg and starts the seeded pool over: a start
// re-mints every seed.
func (l *lab) l2Restart(cfg string) error {
	if err := l.stopDaemon(); err != nil {
		return err
	}
	if err := l.startDaemonWith(cfg, true); err != nil {
		return err
	}
	l.mu.Lock()
	l.tokenN = 0
	l.mu.Unlock()
	return l.awaitTACACS()
}

// l2Denial finds the deny record carrying msg for event.
func l2Denial(recs []map[string]any, event, msg string) map[string]any {
	for _, r := range recs {
		if str(r, "event") == event && str(r, "verdict") == "deny" && str(r, "server_msg") == msg {
			return r
		}
	}
	return nil
}

// l2JunosLogin logs in with a seeded token while every session
// authorization fails, and collects all the device says: an SSH banner, a
// keyboard-interactive name or instruction, the shell's output until the
// device ends it or 30 s pass, and the error. The password is never in it:
// the device does not echo it, and the error names no credential.
func (l *lab) l2JunosLogin(user, password string) string {
	var mu sync.Mutex
	var said strings.Builder
	add := func(what, s string) {
		if strings.TrimSpace(s) == "" {
			return
		}
		mu.Lock()
		fmt.Fprintf(&said, "[%s] %s\n", what, s)
		mu.Unlock()
	}
	cfg := labSSHConfig(user, password)
	cfg.Timeout = 45 * time.Second
	cfg.BannerCallback = func(msg string) error { add("banner", msg); return nil }
	cfg.Auth = []ssh.AuthMethod{
		ssh.Password(password),
		ssh.KeyboardInteractive(func(name, instruction string, questions []string, _ []bool) ([]string, error) {
			add("keyboard-interactive name", name)
			add("keyboard-interactive instruction", instruction)
			answers := make([]string, len(questions))
			for i := range answers {
				answers[i] = password
			}
			return answers, nil
		}),
	}
	nc, err := net.DialTimeout("tcp", l.p.addr+":22", 45*time.Second)
	if err != nil {
		add("error", err.Error())
		return said.String()
	}
	_ = nc.SetDeadline(time.Now().Add(45 * time.Second))
	conn, chans, reqs, err := ssh.NewClientConn(nc, l.p.addr+":22", cfg)
	if err != nil {
		nc.Close()
		add("error", err.Error())
		return said.String()
	}
	_ = nc.SetDeadline(time.Time{})
	c := ssh.NewClient(conn, chans, reqs)
	defer c.Close()
	s, err := c.NewSession()
	if err != nil {
		add("error", "opening a session: "+err.Error())
		return said.String()
	}
	defer s.Close()
	if err := s.RequestPty("vt100", 200, 200, ssh.TerminalModes{ssh.ECHO: 0}); err != nil {
		add("error", "pty: "+err.Error())
		return said.String()
	}
	buf := &syncBuf{}
	s.Stdout, s.Stderr = buf, buf
	if err := s.Shell(); err != nil {
		add("error", "shell: "+err.Error())
		return said.String()
	}
	done := make(chan struct{})
	go func() { s.Wait(); close(done) }()
	select {
	case <-done:
		add("shell, ended by the device", buf.String())
	case <-time.After(30 * time.Second):
		add("shell, still open after 30 s", buf.String())
	}
	return said.String()
}

// l2Row is one length's measurement.
type l2Row struct {
	n       int
	shown   int
	printed string
	record  string
}

func TestL2Truncation(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		sessionOnly := strings.HasPrefix(l.p.name, "juniper_")
		p := l29Heartbeat(t)
		defer p.end()
		// The earlier note's output-modifier observation is kept.
		kept := l2Kept(l.p.name)
		l29RestoreStanding(t, l)
		stop := l.capture(t, "L2")
		defer stop()

		event, base := "authorize_command", denialMessage(shortDenyPrefix)
		if sessionOnly {
			event, base = "authorize_session", l2SessionDenial
		}
		var rows []l2Row
		var bgRows []string
		lockedAt := 0
		var failed []string
		breakglass := func(when string) bool {
			outs, err := l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version")
			said, ok := breakglassRan(l.p.name, outs, err, 1)
			bgRows = append(bgRows, fmt.Sprintf("| %s | %s |", when, said))
			return ok
		}
		if sessionOnly {
			// A baseline, so a break-glass account that never logs in is not
			// read as a length's lockout.
			if err := l.l2Restart(mustL2Config(t, l, 64, true)); err != nil {
				t.Fatal(err)
			}
			p.at(t, "break-glass before any length")
			if !breakglass("before N=64") {
				failed = append(failed, "break-glass did not log in before any length was sent, so Junos past 255 "+
					"bytes cannot be measured safely")
			}
		}
		for _, n := range l2Lengths {
			if sessionOnly && n > 255 {
				if len(failed) > 0 {
					break
				}
				p.at(t, "break-glass before N=%d", n)
				if !breakglass(fmt.Sprintf("before N=%d", n)) {
					lockedAt = rows[len(rows)-1].n
					break
				}
			}
			p.at(t, "N=%d", n)
			if err := l.l2Restart(mustL2Config(t, l, n, sessionOnly)); err != nil {
				t.Fatal(err)
			}
			msg := l2Padded(base, n)
			off := l.mark()
			user, secret, err := l.nextLoginOrErr()
			if err != nil {
				t.Fatal(err)
			}
			var printed string
			if sessionOnly {
				printed = l.l2JunosLogin(user, secret)
			} else {
				sh, err := l.shell(user, secret)
				if err != nil {
					t.Fatalf("N=%d: login as %s: %v", n, user, err)
				}
				out, _, ended, rerr := sh.runOrEnd(shortDenyPrefix, 60*time.Second)
				sh.Close()
				printed = stripPrompt(out)
				if rerr != nil {
					printed += "\n(not observed: " + rerr.Error() + ")"
				} else if ended {
					printed += "\n(the device ended the session)"
				}
			}
			recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
				return l2Denial(rs, event, msg) != nil
			})
			rec := "**no deny record carrying the padded message**"
			if l2Denial(recs, event, msg) != nil {
				rec = fmt.Sprintf("%s deny, %d-byte server_msg", event, len(msg))
			} else {
				failed = append(failed, fmt.Sprintf("N=%d: no %s deny carrying the %d-byte message reached the log",
					n, event, len(msg)))
			}
			rows = append(rows, l2Row{n: n, shown: l2Shown(printed, msg), printed: printed, record: rec})
		}
		if sessionOnly && lockedAt == 0 && len(failed) == 0 {
			p.at(t, "break-glass after N=1000")
			if !breakglass("after N=1000") {
				lockedAt = rows[len(rows)-1].n
			}
		}

		var b strings.Builder
		fmt.Fprintf(&b, "Each length on a port49d of its own, started on the standing lab config with "+
			"`lab.deny_message_length: N`")
		if sessionOnly {
			fmt.Fprintf(&b, " and `lab.deny_session: true`: Junos never authorizes a command (decision 21), so the "+
				"session authorization itself fails with the padded message, and what the login printed is recorded")
		} else {
			fmt.Fprintf(&b, ". A seeded login typed `%s`, which the lab denies", shortDenyPrefix)
		}
		fmt.Fprintf(&b, ". The message is `%s`, a space, and `0123456789` repeated to N bytes, so the last digit "+
			"shown says where the device cut.\n\n", base)
		fmt.Fprintf(&b, "| N (bytes) | The record | Longest prefix shown | What the device printed |\n|---|---|---|---|\n")
		maxShown, full := 0, 0
		for _, r := range rows {
			shown := fmt.Sprintf("%d", r.shown)
			if r.shown == r.n {
				shown += " (all of it)"
				full++
			}
			maxShown = max(maxShown, r.shown)
			fmt.Fprintf(&b, "| %d | %s | %s | %s |\n", r.n, r.record, shown, l29Cell(r.printed))
		}
		display := ""
		switch {
		case len(rows) == 0:
			display = "**Not measured:** no length was sent."
		case maxShown == 0 && sessionOnly:
			display = "**Not measurable: session-only (decision 21).** The session denial carried the padded " +
				"message at every length, and the login printed none of it, so the device's display and its " +
				"truncation length are not observed on this image."
		case maxShown == 0:
			display = fmt.Sprintf("**Not displayed** at any length: the device printed no %d-byte prefix of the "+
				"message, so its truncation length cannot be read.", l2MinShown)
		case full == len(rows):
			display = fmt.Sprintf("**Displayed in full** at every length measured, up to %d bytes: no truncation "+
				"at or below %d bytes.", rows[len(rows)-1].n, rows[len(rows)-1].n)
		default:
			display = fmt.Sprintf("**Displayed, truncated:** the longest prefix shown is %d bytes.", maxShown)
		}
		fmt.Fprintf(&b, "\n%s\n", display)
		if sessionOnly {
			fmt.Fprintf(&b, "\n### Break-glass past 255 bytes\n\nThe owner's production prior: on Junos a reply "+
				"over 255 bytes locked the user out. Break-glass was proved before each length over 255 and after "+
				"the last, the run stopping at the first length that left it refused.\n\n| When | Break-glass |\n"+
				"|---|---|\n%s\n", strings.Join(bgRows, "\n"))
			if lockedAt > 0 {
				fmt.Fprintf(&b, "\n**Finding:** after N=%d the device refused break-glass.\n", lockedAt)
			}
		}
		if kept != "" {
			fmt.Fprintf(&b, "\n%s\n%s\n", l2KeptHeader, kept)
		}
		fmt.Fprintf(&b, "\n%s\n", l29Built())
		if len(failed) > 0 {
			fmt.Fprintf(&b, "\n**Not measured as the brief says:**\n\n- %s\n", strings.Join(failed, "\n- "))
		}
		l.result(t, "L2", l2Claim, b.String())
		p.end()
		if len(failed) > 0 {
			t.Fatalf("%d length(s) not measured (the note records them): %v", len(failed), failed)
		}
	})
}

func mustL2Config(t *testing.T, l *lab, n int, denySession bool) string {
	t.Helper()
	cfg, err := l.l2Config(n, denySession)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
