//go:build lab

package lab

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	adapter "github.com/rhwendt/port49/internal/platform"
)

// TestAdapterCarried is the rest of L22 (plan 5a, Task 17): the measurements
// the controller carried into the run beside TestAdapterReplies. It records,
// and it judges nothing: each row is read against the adapter's promise in
// the task report, and a contradiction there is a finding for a ruling, not
// a test to loosen.
//
//   - check-config fidelity: the running configuration each node carries as
//     the lab deployed it, read by `port49 devices check-config` for the
//     platform's shipped adapter. A false MISSING or a false CONFIG finding
//     is a defect in platforms/1.0.0 (CLAUDE.md rule 4).
//   - EOS: the pair `priv-lvl=1` + `roles=network-operator` (readonly's
//     rendering), with the role read from a second session, because at level
//     1 the parser refuses `show users detail`.
//   - NX-OS: the role alone in the quoted optional spelling,
//     `shell:roles*"network-operator"` and, as the control, network-admin's.
//   - At fallback, under operator's reply and admin's: `clear counters` and
//     `clear ip bgp *` as well as the configuration change.
//   - IOS-XE: level 7 without `aaa authorization commands 7 ...`: whether a
//     level-7 command then reaches port49 at all.
//
// The note is L22-carried-<platform>.md, with its own capture.
func TestAdapterCarried(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if _, ok := adapterExpect[l.p.name]; !ok {
			t.Skipf("%s renders no level until plan 5b's projection", l.p.name)
		}
		d, _ := adapter.DialectFor(l.p.name)
		stop := l.capture(t, "L22-carried")
		defer stop()
		defer func() {
			std, err := l.configPath()
			if err == nil {
				err = l.restart(std)
			}
			if err != nil {
				t.Fatalf("could not put port49d back on the lab config: %v", err)
			}
		}()
		var obs strings.Builder

		obs.WriteString("### check-config against the device's own running configuration\n\n")
		l.carriedCheckConfig(t, &obs, "lab", nil)

		switch l.p.name {
		case "arista_eos":
			l.carriedEOSPair(t, &obs)
			// A second look at `home-directory` beside admin's reply: the
			// first run's identity line came back empty (L22-arista_eos.md).
			admin, _ := d.Render("admin")
			attrs := append(admin, "home-directory*/home/port49")
			row := l.adapterVariant(t, "carried-home-directory", attrs)
			fmt.Fprintf(&obs, "\n### EOS: `home-directory*/home/port49` beside admin's reply, again\n\n"+
				"| reply | session | identity | `clear counters` | `configure terminal` | `show version` |\n"+
				"|---|---|---|---|---|---|\n| `%s` | %s | `%s` | %s | %s | %s |\n", strings.Join(attrs, "`, `"),
				row.session, row.identity, row.reach("clear counters", row.clear),
				row.reach("configure terminal", row.cfg), row.permit(row.showVersion))
		case "cisco_nxos":
			obs.WriteString("\n### NX-OS: the role alone, quoted optional spelling\n\n" +
				"| reply | session | identity | `clear counters` | `configure terminal` | `show version` |\n" +
				"|---|---|---|---|---|---|\n")
			for _, role := range []string{"network-operator", "network-admin"} {
				attrs := []string{`shell:roles*"` + role + `"`}
				row := l.adapterVariant(t, "quoted-"+role, attrs)
				fmt.Fprintf(&obs, "| `%s` | %s | `%s` | %s | %s | %s |\n", attrs[0], row.session, row.identity,
					row.reach("clear counters", row.clear), row.reach("configure terminal", row.cfg),
					row.permit(row.showVersion))
			}
		}

		// BGP, so that `clear ip bgp *` is a command the parser has on NX-OS
		// and has something to clear on IOS-XE, as the ceiling notes had it.
		// vEOS cannot run BGP (ceiling-arista_eos.md).
		switch l.p.name {
		case "cisco_nxos":
			l.carriedConfigure(t, "feature bgp", "router bgp 65000", "neighbor 192.0.2.2", "remote-as 65001")
		case "cisco_iosxe":
			l.carriedConfigure(t, "router bgp 65000", "neighbor 192.0.2.2 remote-as 65001")
		}
		fmt.Fprintf(&obs, "\n### Fallback, each command typed after port49d stopped under the open session\n\n"+
			"Each command's verbatim reply, from the line typed to the next prompt. The device's command method "+
			"list ends in `local` (tests/lab/configs/*-startup.cfg).\n\n")
		for _, level := range []string{"operator", "admin"} {
			attrs, _ := d.Render(level)
			fmt.Fprintf(&obs, "#### %s: `%s`\n\n", level, strings.Join(attrs, "`, `"))
			obs.WriteString(l.fallbackCommands(t, level, attrs))
		}

		if l.p.name == "cisco_iosxe" {
			l.carriedIOSXENoLevel7List(t, &obs, d)
		}

		l.result(t, "L22-carried", "The measurements carried into Task 17 beside the adapters' replies: "+
			"`port49 devices check-config` against the node's own running configuration; on EOS the identity "+
			"`priv-lvl=1` + `roles=network-operator` gives; on NX-OS whether the quoted optional "+
			"`shell:roles*\"<role>\"` alone sets the role; at fallback, `clear counters` and `clear ip bgp *` "+
			"beside the configuration change under operator's reply and admin's; and on IOS-XE whether a "+
			"level-7 command reaches port49 without `aaa authorization commands 7` (plan 5a, Task 17; spec §6, "+
			"§15 L22; decision 25).", obs.String())
	})
}

// adminCLI opens this platform's break-glass CLI: the opener withAdminCLI
// takes.
func adminCLI(l *lab) (*cliConn, error) {
	switch l.p.name {
	case "cisco_nxos":
		return l.nxosCLI(breakglassUser, breakglassPassword)
	case "cisco_iosxe":
		return l.iosxeCLI(breakglassUser, breakglassPassword)
	}
	return l.eosCLI(breakglassUser, breakglassPassword)
}

func (l *lab) adminShow(c *cliConn, cmd string) (string, error) {
	switch l.p.name {
	case "cisco_nxos":
		return nxosShow(c, cmd)
	case "cisco_iosxe":
		return iosxeShow(c, cmd)
	}
	return eosShow(c, cmd)
}

// carriedConfigure types lines in configuration mode over the break-glass
// CLI, waiting for any configuration prompt: a `router bgp` line changes it,
// which the per-platform helpers do not expect.
func (l *lab) carriedConfigure(t *testing.T, lines ...string) string {
	t.Helper()
	var out string
	l.withAdminCLI(t, adminCLI, func(c *cliConn) error {
		from := len(c.transcript())
		cfg := l.p.node + "(config"
		if _, err := c.sendExpect("configure terminal", 45*time.Second, cfg); err != nil {
			return err
		}
		for _, ln := range lines {
			got, err := c.sendExpect(ln, 60*time.Second, cfg)
			if err != nil {
				return fmt.Errorf("%q: %w", ln, err)
			}
			if strings.Contains(got, "% ") || strings.Contains(got, "ERROR") {
				return fmt.Errorf("%q was refused by the device:\n%s", ln, got)
			}
		}
		if _, err := c.sendExpect("end", 45*time.Second, c.prompt); err != nil {
			return err
		}
		out = c.transcript()[from:]
		return nil
	})
	return out
}

// checkConfigShows is what each platform's configuration is read from:
// `show running-config`, and the AAA section the way an operator would
// fetch it on its own.
var checkConfigShows = map[string][]string{
	"arista_eos":  {"show running-config"},
	"cisco_nxos":  {"show running-config", "show running-config aaa"},
	"cisco_iosxe": {"show running-config", "show running-config | section aaa"},
}

// secretWord is a configuration word followed by a secret: the value (and an
// encryption-type word before it) is replaced before a capture is committed.
var secretWord = regexp.MustCompile(`(?i)\b(secret|key|password|passphrase|community)(\s+(?:\d+|sha512|md5)\b)?(\s+)("[^"]*"|\S+)`)

// redactConfigCapture hides every secret-bearing value in a configuration
// capture: the lab's are published constants, but a committed capture is
// read as if it came off a real device.
func redactConfigCapture(s string) string {
	s = snmpKey.ReplaceAllString(s, "${1}${2}<removed>")
	return secretWord.ReplaceAllString(s, "${1}${2}${3}<removed>")
}

// snmpKey is an SNMPv3 user's localized auth or priv key, which NX-OS prints
// in hex after the algorithm: derived from the user's password, so a secret.
var snmpKey = regexp.MustCompile(`(?i)\b((?:auth|priv)\s+(?:md5|sha\S*|aes-?\d*|des|3des))(\s+)(\S+)`)

// cleanShow is a show command's output with the echoed command line, the
// trailing prompt and carriage returns removed.
func cleanShow(out, prompt string) string {
	out = strings.ReplaceAll(out, "\r", "")
	lines := strings.Split(out, "\n")
	if len(lines) > 0 {
		lines = lines[1:]
	}
	for len(lines) > 0 {
		last := strings.TrimSpace(lines[len(lines)-1])
		if last == "" || strings.HasPrefix(last, prompt) {
			lines = lines[:len(lines)-1]
			continue
		}
		break
	}
	return strings.Join(lines, "\n") + "\n"
}

// carriedCheckConfig captures the node's configuration over the break-glass
// CLI (port49d stopped, withAdminCLI), keeps the raw text under
// tests/lab/logs and a redacted copy under tests/lab/evidence, and runs
// `port49 devices check-config` on both, writing each finding into obs.
// label names the device state; want, when set, is a MISSING line the
// state is known to lack.
func (l *lab) carriedCheckConfig(t *testing.T, obs *strings.Builder, label string, want []string) {
	t.Helper()
	port49 := filepath.Join(root, "bin", "port49")
	if _, err := os.Stat(port49); err != nil {
		t.Fatalf("bin/port49 is not built (`make build`): %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "tests", "lab", "logs"), 0o755); err != nil {
		t.Fatal(err)
	}
	captures := map[string]string{}
	l.withAdminCLI(t, adminCLI, func(c *cliConn) error {
		for _, cmd := range checkConfigShows[l.p.name] {
			out, err := l.adminShow(c, cmd)
			if err != nil {
				return fmt.Errorf("%s: %w", cmd, err)
			}
			captures[cmd] = cleanShow(out, strings.TrimSuffix(c.prompt, "#"))
		}
		return nil
	})
	for i, cmd := range checkConfigShows[l.p.name] {
		base := fmt.Sprintf("L22-config-%s-%s-%d.txt", l.p.name, label, i+1)
		raw := filepath.Join(root, "tests", "lab", "logs", base)
		ev := filepath.Join(root, "tests", "lab", "evidence", base)
		if err := os.WriteFile(raw, []byte(captures[cmd]), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ev, []byte(redactConfigCapture(captures[cmd])), 0o644); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(obs, "`%s` (%s), %d lines, redacted copy `tests/lab/evidence/%s`:\n\n", cmd, label,
			strings.Count(captures[cmd], "\n"), base)
		for _, file := range []string{raw, ev} {
			cc := exec.Command(port49, "devices", "check-config", "--policy",
				filepath.Join(root, "tests", "lab", "slice", "policy.yaml"), "--inventory",
				filepath.Join(root, "tests", "lab", "inventory-lab.yaml"), "--device", l.p.node, file)
			out, _ := cc.CombinedOutput()
			which := "the raw capture"
			if file == ev {
				which = "the redacted copy"
			}
			text := strings.ReplaceAll(string(out), file, "<capture>")
			fmt.Fprintf(obs, "check-config on %s, exit %d:\n\n```\n%s```\n\n", which, cc.ProcessState.ExitCode(), text)
			for _, w := range want {
				if !strings.Contains(text, "MISSING: <capture>: "+w+":") {
					t.Errorf("check-config on %s (%s) did not report %q MISSING", which, label, w)
				}
			}
		}
	}
}

// carriedEOSPair delivers readonly's pair, priv-lvl=1 + roles=network-operator,
// holds the session open, and reads the role EOS gave it from a second
// session at admin's reply: at level 1 the parser refuses `show users
// detail` (the adapter's unreachable list).
func (l *lab) carriedEOSPair(t *testing.T, obs *strings.Builder) {
	t.Helper()
	pair := []string{"priv-lvl=1", "roles=network-operator"}
	quoted, _ := json.Marshal(pair)
	cfg, err := l.derivedConfig("carried-pair", string(quoted), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.restart(cfg); err != nil {
		t.Fatalf("port49d would not start: %v", err)
	}
	user, secret := l.nextLogin(t)
	off := l.mark()
	c, err := l.sshCLI(user, secret)
	if err != nil {
		fmt.Fprintf(obs, "\n### EOS: `priv-lvl=1` + `roles=network-operator`\n\nsession refused: %v\n", err)
		return
	}
	defer c.Close()
	c.prompt = l.p.node + ">"
	_, _ = c.expect(45*time.Second, l.p.node+">", l.p.node+"#")
	priv, _ := c.sendExpect("show privilege", 30*time.Second, l.p.node+">", l.p.node+"#")
	sud, _ := c.sendExpect("show users detail", 30*time.Second, l.p.node+">", l.p.node+"#")
	recs := l.drainRecords(off, 3*time.Second)
	sessionPriv := ""
	for _, r := range recs {
		if str(r, "event") == "authorize_session" {
			sessionPriv = fmt.Sprint(sub(r, "session")["privilege"])
		}
	}

	admin, _ := adapter.DialectFor(l.p.name)
	adminAttrs, _ := admin.Render("admin")
	quoted, _ = json.Marshal(adminAttrs)
	cfg, err = l.derivedConfig("carried-pair-reader", string(quoted), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.restart(cfg); err != nil {
		t.Fatalf("port49d would not start: %v", err)
	}
	reader, readerSecret := l.nextLogin(t)
	outs, err := l.loginWithin(reader, readerSecret, 150*time.Second, "show users detail")
	users := ""
	if err != nil {
		users = "reader session refused: " + err.Error()
	} else if len(outs) > 0 {
		users = outs[0]
	}
	fmt.Fprintf(obs, "\n### EOS: `priv-lvl=1` + `roles=network-operator` (readonly's rendering)\n\n"+
		"Session `%s`, held open with a pty (the request's privilege on the session authorization: %s).\n\n"+
		"In it:\n\n```\n%s\n%s\n```\n\n"+
		"`show users detail` from a second session, `%s`, at admin's reply (`%s`):\n\n```\n%s\n```\n",
		user, carriedValue(sessionPriv), strings.TrimSpace(strings.ReplaceAll(priv, "\r", "")),
		strings.TrimSpace(strings.ReplaceAll(sud, "\r", "")), reader, strings.Join(adminAttrs, "`, `"),
		strings.TrimSpace(strings.ReplaceAll(users, "\r", "")))
}

func carriedValue(s string) string {
	if s == "" {
		return "not recorded"
	}
	return "`" + s + "`"
}

// fallbackCommands delivers attrs, opens one pty session, stops port49d under
// it, and types `clear counters`, `clear ip bgp *`, `configure terminal` and
// `hostname <node>` (the value the device already holds), returning each
// command's verbatim reply. On IOS-XE `clear counters` asks `[confirm]`, and
// `n` declines it: local authorization has already answered by then.
func (l *lab) fallbackCommands(t *testing.T, level string, attrs []string) string {
	t.Helper()
	quoted, _ := json.Marshal(attrs)
	cfg, err := l.derivedConfig("carried-fallback-"+level, string(quoted), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.restart(cfg); err != nil {
		t.Fatalf("fallback %s: port49d would not start: %v", level, err)
	}
	user, secret := l.nextLogin(t)
	c, err := l.sshCLI(user, secret)
	if err != nil {
		return fmt.Sprintf("session refused: %v\n\n", err)
	}
	defer c.Close()
	prompts := []string{l.p.node + "#", l.p.node + ">", l.p.node + "(config"}
	c.prompt = l.p.node
	if _, err := c.expect(60*time.Second, prompts...); err != nil {
		return fmt.Sprintf("no prompt: %v\n\n", err)
	}
	if l.p.name != "cisco_iosxe" {
		_, _ = c.sendExpect("terminal length 0", 30*time.Second, prompts...)
	}
	ident := "show privilege"
	if l.p.name == "cisco_nxos" {
		ident = "show user-account " + user
	}
	before, _ := c.sendExpect(ident, 30*time.Second, prompts...)
	if err := l.stopDaemon(); err != nil {
		return fmt.Sprintf("port49d would not stop: %v\n\n", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Session `%s`, before port49d stopped:\n\n```\n%s\n```\n\n", user,
		strings.TrimSpace(strings.ReplaceAll(before, "\r", "")))
	b.WriteString("| typed | reply after port49d stopped |\n|---|---|\n")
	for _, line := range []string{"clear counters", "clear ip bgp *", "configure terminal", "hostname " + l.p.node, "end"} {
		want := append([]string{"[confirm]"}, prompts...)
		out, err := c.sendExpect(line, 45*time.Second, want...)
		if strings.Contains(out, "[confirm]") {
			more, _ := c.sendExpect("n", 30*time.Second, prompts...)
			out += more
		}
		if err != nil {
			out += " (no prompt within 45s)"
		}
		fmt.Fprintf(&b, "| `%s` | `%s` |\n", line,
			strings.ReplaceAll(strings.TrimSpace(strings.ReplaceAll(out, "\r", "")), "\n", " ⏎ "))
	}
	b.WriteString("\n")
	return b.String()
}

// carriedIOSXENoLevel7List removes `aaa authorization commands 7 default
// group port49 local`, reads the configuration with check-config (which
// must report the line MISSING), logs in at operator's reply and runs the
// level-7 command, and puts the line back.
func (l *lab) carriedIOSXENoLevel7List(t *testing.T, obs *strings.Builder, d adapter.Dialect) {
	t.Helper()
	const list = "aaa authorization commands 7 default group port49 local"
	obs.WriteString("\n### IOS-XE: level 7 without `" + list + "`\n\n")
	l.carriedConfigure(t, "no "+list)
	defer l.carriedConfigure(t, list)
	l.carriedCheckConfig(t, obs, "no-commands-7", []string{list})
	attrs, _ := d.Render("operator")
	quoted, _ := json.Marshal(attrs)
	cfg, err := l.derivedConfig("carried-no-commands-7", string(quoted), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.restart(cfg); err != nil {
		t.Fatalf("port49d would not start: %v", err)
	}
	user, secret := l.nextLogin(t)
	off := l.mark()
	outs, err := l.loginWithin(user, secret, 150*time.Second, "show privilege", "clear counters", "show version")
	recs := l.drainRecords(off, 3*time.Second)
	if err != nil {
		fmt.Fprintf(obs, "operator's session refused: %v\n", err)
		return
	}
	fmt.Fprintf(obs, "Operator's reply `%s`, session `%s`, the commands typed in one pty session (IOS-XE runs one exec channel per connection):\n\n",
		strings.Join(attrs, "`, `"), user)
	for i, cmd := range []string{"show privilege", "clear counters", "show version"} {
		out := ""
		if i < len(outs) {
			out = strings.TrimSpace(strings.ReplaceAll(outs[i], "\r", ""))
		}
		if i == 2 {
			out = strings.SplitN(out, "\n", 2)[0] + " …"
		}
		fmt.Fprintf(obs, "`%s`:\n\n```\n%s\n```\n\n", cmd, carriedReply(out))
	}
	obs.WriteString("Every `authorize_command` record port49 wrote for the session:\n\n| vector | verdict | reason |\n|---|---|---|\n")
	n := 0
	for _, r := range recs {
		if str(r, "event") != "authorize_command" {
			continue
		}
		n++
		fmt.Fprintf(obs, "| `%s` | %s | %s |\n", strings.Join(strs(sub(r, "request"), "vector"), " "),
			str(r, "verdict"), str(r, "reason"))
	}
	if n == 0 {
		obs.WriteString("| (none) | | |\n")
	}
}

func carriedReply(s string) string {
	if s == "" {
		return emptyDeviceReply
	}
	return s
}
