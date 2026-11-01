//go:build lab

package lab

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/testpki"
	"github.com/blanketfish/port49/tests/lab/labcreds"
)

// Plan 7b's session run (Task 12): a role ceiling short enough to wait out,
// the warning before it, `port49 refresh`, the ceiling, and the grace window
// after it, on a real device.

const l34Claim = "Whether a device shows the `server_msg` port49 puts on a **permitted** authorization reply — " +
	"the session reply at login, and a per-command reply — and still treats the reply as a permit: the " +
	"command's output appears and the session goes on."

const sessionClaim = "Spec §13 decision 33, its session clauses. **The warning** rides on permits within " +
	"`session.ceiling_warning` of the ceiling, to the platforms L34 finds show it and any an operator lists " +
	"(`session.ceiling_warning_platforms`), and on `port49 token`'s stderr everywhere. **Past the ceiling** a " +
	"context is kept through the grace window and deleted at its first authorization after it, and the store " +
	"refuses to extend one past it. **The refresh** is a single-use 60s nonce signed over the connection's TLS " +
	"exporter value; it extends only contexts the policy in force has just judged and kept, and only an " +
	"operator's `port49 refresh` or `port49 login` triggers it."

// sessionPolicyFile is the slice policy with `max_session_age: 6m` on
// network_admin; sessionBlock is the session clocks the run waits out:
// the warning 2m before the 6m ceiling, the grace window 2m after it. The
// platform list puts every lab platform on the warning's allow-list for the
// measurement, unmeasured ones included (Ruling 4).
const (
	sessionPolicyFile = "tests/lab/slice/session-policy.yaml"
	sessionBlock      = "  ceiling_warning: 2m\n  grace_window: 2m\n" +
		"  ceiling_warning_platforms: [arista_eos, cisco_nxos, cisco_iosxe, juniper_junos]\n"
	sessionCeiling = 6 * time.Minute
	sessionGrace   = 2 * time.Minute
)

// sessionWarning starts the warning's server_msg (internal/daemon/author);
// sessionExpiredMsg and sessionEndedMsg start a session_expired denial's,
// inside and past the grace window.
const (
	sessionWarning    = "port49: session ends in"
	sessionExpiredMsg = "port49: session expired"
	sessionEndedMsg   = "port49: session ended"
)

// sessionVersion is revokeVersion with vSRX's line (L26c-juniper_vsrx.md).
var sessionVersion = map[string]string{
	"arista_eos":            "Arista vEOS",
	"cisco_nxos":            "Cisco Nexus Operating System (NX-OS) Software",
	"cisco_iosxe":           "Cisco IOS XE Software",
	"juniper_vjunos-router": "Junos:",
	"juniper_vsrx":          "Junos:",
}

var extendedTo = regexp.MustCompile(`extended to (\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)`)

// sessionConfig derives the slice config with the broker reading
// sessionPolicyFile and sessionBlock merged into the `session:` key: under
// the derived file's own key if it has one, never as a second (pre-flight M9).
func (l *lab) sessionConfig() (string, error) {
	brokerYAML, err := os.ReadFile(filepath.Join(root, "tests", "lab", "slice", "broker.yaml"))
	if err != nil {
		return "", err
	}
	b := string(brokerYAML)
	if !strings.Contains(b, "  policy_file: tests/lab/slice/policy.yaml\n") {
		return "", fmt.Errorf("tests/lab/slice/broker.yaml no longer reads tests/lab/slice/policy.yaml, so the session " +
			"policy cannot be swapped in")
	}
	b = strings.Replace(b, "  policy_file: tests/lab/slice/policy.yaml\n", "  policy_file: "+sessionPolicyFile+"\n", 1)
	cfg, err := l.derivedConfig("session", platformSessionAttributes[l.p.name], b)
	if err != nil {
		return "", err
	}
	raw, err := os.ReadFile(cfg)
	if err != nil {
		return "", err
	}
	out := string(raw)
	if i := strings.Index(out, "\nsession:\n"); i >= 0 {
		at := i + len("\nsession:\n")
		out = out[:at] + sessionBlock + out[at:]
	} else {
		out += "\nsession:\n" + sessionBlock
	}
	return cfg, os.WriteFile(cfg, []byte(out), 0o644)
}

// sessionMint asks the agent for a token for device. tok is the token, or
// "" with err; warn is what `port49 token` said on stderr, which never
// holds the token. The token is never printed.
func sessionMint(sock, device string) (tok, warn string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := withAgent(exec.CommandContext(ctx, filepath.Join(root, "bin", "port49"), "token", device), sock)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, runErr := cmd.Output()
	warn = strings.TrimSpace(stderr.String())
	if s := strings.TrimSpace(string(out)); runErr == nil && len(s) == labcreds.TokenLen {
		return s, warn, nil
	}
	return "", warn, fmt.Errorf("port49 token %s: %v, %d characters on stdout; stderr: %s", device, runErr, len(out), warn)
}

// refreshCLI runs `port49 refresh` against the agent at sock: what it
// printed, and whether it exited 0. Its output names devices and times,
// never a credential.
func refreshCLI(sock string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	out, err := withAgent(exec.CommandContext(ctx, filepath.Join(root, "bin", "port49"), "refresh"), sock).CombinedOutput()
	return strings.TrimSpace(string(out)), err == nil
}

// sessionStep is one `show version` in the held session, read for the
// note: whether its output appeared, whether it was refused, whether the
// session ended, and the lines carrying port49's text or the device's
// refusal.
type sessionStep struct {
	out     string
	took    time.Duration
	ended   bool
	err     error
	printed bool // the platform's show version line appeared
	refused bool
	warned  bool // sessionWarning appeared
}

func runSessionStep(platform string, sh *labShell, cmd string) sessionStep {
	s := sessionStep{}
	if sh == nil {
		s.err = fmt.Errorf("no session to run it in")
		return s
	}
	s.out, s.took, s.ended, s.err = sh.runOrEnd(cmd, 60*time.Second)
	s.printed = sessionVersion[platform] != "" && strings.Contains(s.out, sessionVersion[platform])
	// IOS-XE prints a FAIL's server_msg and nothing else
	// (results/slice-cisco_iosxe.md), so port49's text without the
	// command's output is a refusal there.
	s.refused = l29Refused(platform, s.out) || strings.Contains(s.out, sessionExpiredMsg) ||
		strings.Contains(s.out, sessionEndedMsg) ||
		(platform == "cisco_iosxe" && !s.printed && strings.Contains(s.out, "port49: "))
	s.warned = strings.Contains(s.out, sessionWarning)
	return s
}

// text is the lines of the step's output that carry port49's text or the
// platform's refusal: what the device showed of a server_msg.
func (s sessionStep) text(platform string) string {
	var keep []string
	for _, line := range strings.Split(strings.ReplaceAll(s.out, "\r", ""), "\n") {
		if strings.Contains(line, "port49") || l29Refused(platform, line) {
			keep = append(keep, strings.TrimSpace(line))
		}
	}
	if len(keep) == 0 {
		return "no port49 text and no refusal"
	}
	return l29Cell(strings.Join(keep, " / "))
}

// cell says what happened, for a table cell. A deadline is "not observed",
// never a pass.
func (s sessionStep) cell(platform string) string {
	d := s.took.Round(10 * time.Millisecond)
	switch {
	case s.err != nil:
		return "**not observed**: " + l29Cell(s.err.Error())
	case s.ended:
		return fmt.Sprintf("the device ended the session after %s; it printed %s", d, l29Cell(s.out))
	case s.refused:
		return fmt.Sprintf("refused in %s; the device printed %s", d, s.text(platform))
	case s.printed:
		return fmt.Sprintf("its output appeared in %s; port49's text: %s", d, s.text(platform))
	}
	return fmt.Sprintf("printed something in %s without %q: %s", d, sessionVersion[platform], l29Cell(firstLine(s.out)))
}

// lastRecord is the last record of event about slice01 in recs, or nil.
func lastRecord(recs []map[string]any, event string) map[string]any {
	rs := sliceRecords(recs, event, "")
	if len(rs) == 0 {
		return nil
	}
	return rs[len(rs)-1]
}

// recordCell is a record's verdict, reason and server_msg, for a table cell.
func recordCell(r map[string]any) string {
	if r == nil {
		return "no record"
	}
	msg := str(r, "server_msg")
	if msg == "" {
		msg = "(none)"
	}
	return fmt.Sprintf("%s %s, server_msg %s", str(r, "verdict"), str(r, "reason"), l29Cell(msg))
}

// sessionWaitUntil sleeps to at, saying so to the heartbeat; it fails the
// test, so its cleanups run, when go test's -timeout would end it first.
func sessionWaitUntil(t *testing.T, p *l29Progress, at time.Time, what string) {
	t.Helper()
	d := time.Until(at)
	if d <= 0 {
		p.at(t, "%s: already past (%s late)", what, (-d).Round(time.Second))
		return
	}
	l29Budget(t, d+5*time.Minute)
	p.at(t, "waiting %s, until %s, for %s", d.Round(time.Second), l29Clock(at), what)
	time.Sleep(d)
}

// prePrompt is what the device said before its first prompt: on login, the
// session reply's server_msg, if the device shows one.
func prePrompt(sh *labShell) string {
	s := sh.c.transcript()
	cut := len(s)
	for _, p := range sh.prompts {
		if i := strings.Index(s, p); i >= 0 && i < cut {
			cut = i
		}
	}
	return s[:cut]
}

func TestSessionLifetime(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		var failed []string
		fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
		sessionOnly := strings.HasPrefix(l.p.name, "juniper_")
		p := l29Heartbeat(t)
		defer p.end()

		pki := filepath.Join(root, slicePKIDir)
		if err := testpki.WriteLab(pki, sliceEmail, time.Now()); err != nil {
			t.Fatal(err)
		}
		cfg, err := l.sessionConfig()
		if err != nil {
			t.Fatal(err)
		}
		if err := l.stopDaemon(); err != nil {
			t.Fatal(err)
		}
		if err := l.startDaemonWith(cfg, true); err != nil {
			t.Fatalf("port49d would not start with the session policy and block: %v", err)
		}
		if err := l.awaitTACACS(); err != nil {
			t.Fatal(err)
		}
		l29RestoreStanding(t, l)
		stop := l.capture(t, "session")
		defer stop()
		off := l.mark()

		// 1–2. port49 login, then into the warning: the ceiling runs from the
		// held connection's handshake, inside `port49 login`.
		p.at(t, "port49 login")
		loginAt := time.Now()
		sock, _, stopAgent := revokeAgent(t)
		defer stopAgent()
		sessionWaitUntil(t, p, loginAt.Add(4*time.Minute+10*time.Second), "the 2m warning before the 6m ceiling")

		// 3. A login inside the warning.
		p.at(t, "mint and log in inside the warning")
		tok, mintWarn, err := sessionMint(sock, l.p.node)
		if err != nil {
			t.Fatalf("the agent minted no token inside the warning: %v\nrecords:%s", err, summarize(l.recordsSince(off)))
		}
		offLogin := l.mark()
		sh, loginErr := l.shell(sliceUser, tok)
		loginCell := ""
		var preText string
		switch {
		case loginErr != nil:
			// A device that turns the permit into anything but a permit is
			// L34's finding, not a failure to retry.
			loginCell = "**the login did not reach a prompt**: " + l29Cell(loginErr.Error())
		default:
			defer sh.Close()
			preText = prePrompt(sh)
			if strings.Contains(preText, sessionWarning) {
				loginCell = "reached a prompt; before it the device showed " + l29Cell(lineWith(preText, sessionWarning))
			} else {
				loginCell = "reached a prompt; **the warning was not observed** before it (the text before the " +
					"prompt: " + l29Cell(preText) + ")"
			}
		}
		recs := l.waitForRecords(offLogin, 30*time.Second, func(rs []map[string]any) bool {
			return lastRecord(rs, "authorize_session") != nil
		})
		sessRec := lastRecord(recs, "authorize_session")
		if sessRec == nil || !strings.HasPrefix(str(sessRec, "server_msg"), sessionWarning) || str(sessRec, "verdict") != "permit" {
			fail("the login's authorize_session is not a permit carrying the warning: %s", recordCell(sessRec))
		}

		// 4. A command inside the warning.
		p.at(t, "show version inside the warning")
		offCmd := l.mark()
		inWarn := runSessionStep(l.p.name, sh, "show version")
		cmdRec := lastRecord(l.waitForRecords(offCmd, 15*time.Second, func(rs []map[string]any) bool {
			return sessionOnly || lastRecord(rs, "authorize_command") != nil
		}), "authorize_command")
		switch {
		case sessionOnly && cmdRec != nil:
			fail("Junos authorized a command (decision 21 says it never does): %s", recordCell(cmdRec))
		case !sessionOnly && (cmdRec == nil || !strings.HasPrefix(str(cmdRec, "server_msg"), sessionWarning)):
			fail("the command's authorize_command is not a permit carrying the warning: %s", recordCell(cmdRec))
		}

		// 5. The refresh: no warning after it, and the output appears.
		p.at(t, "port49 refresh")
		offRef := l.mark()
		refreshed, refOK := refreshCLI(sock)
		if !refOK {
			fail("port49 refresh: %s", refreshed)
		}
		extended := extendedTo.FindAllStringSubmatch(refreshed, -1)
		if len(extended) != 1 || (sessionOnly && !strings.Contains(refreshed, "not reached")) ||
			(!sessionOnly && strings.Contains(refreshed, "not reached")) {
			fail("the refresh did not name one extended session (and, on Junos only, not reached): %q", refreshed)
		}
		expires := loginAt.Add(10 * sessionCeiling) // never reached if the refresh said nothing
		if len(extended) == 1 {
			if at, err := time.Parse(time.RFC3339, extended[0][1]); err == nil {
				expires = at
			}
		}
		offAfter := l.mark()
		afterRef := runSessionStep(l.p.name, sh, "show version")
		afterRec := lastRecord(l.waitForRecords(offAfter, 15*time.Second, func(rs []map[string]any) bool {
			return sessionOnly || lastRecord(rs, "authorize_command") != nil
		}), "authorize_command")
		if !sessionOnly && (afterRec == nil || str(afterRec, "verdict") != "permit" || str(afterRec, "server_msg") != "") {
			fail("the command after the refresh is not a bare permit: %s", recordCell(afterRec))
		}
		if afterRef.warned {
			fail("the device showed the warning after the refresh")
		}
		refRecs := sliceRecords(l.recordsSince(offRef), "refresh", "")

		// 6. Past the ceiling, inside the grace window.
		sessionWaitUntil(t, p, expires.Add(10*time.Second), "the ceiling, plus 10 s")
		offPast := l.mark()
		past := runSessionStep(l.p.name, sh, "show version")
		pastRec := lastRecord(l.waitForRecords(offPast, 15*time.Second, func(rs []map[string]any) bool {
			return sessionOnly || lastRecord(rs, "authorize_command") != nil
		}), "authorize_command")
		if !sessionOnly && (pastRec == nil || str(pastRec, "reason") != "session_expired" ||
			!strings.HasPrefix(str(pastRec, "server_msg"), sessionExpiredMsg)) {
			fail("the command past the ceiling was not denied session_expired inside the grace window: %s", recordCell(pastRec))
		}

		// 7. Resumed inside the grace window.
		p.at(t, "port49 refresh inside the grace window")
		resumed, ok := refreshCLI(sock)
		if !ok {
			fail("port49 refresh inside the grace window: %s", resumed)
		}
		again := extendedTo.FindAllStringSubmatch(resumed, -1)
		if len(again) != 1 {
			fail("the refresh inside the grace window did not name one extended session: %q", resumed)
		}
		expires2 := expires.Add(10 * sessionCeiling)
		if len(again) == 1 {
			if at, err := time.Parse(time.RFC3339, again[0][1]); err == nil {
				expires2 = at
			}
		}
		offRes := l.mark()
		res := runSessionStep(l.p.name, sh, "show version")
		resRec := lastRecord(l.waitForRecords(offRes, 15*time.Second, func(rs []map[string]any) bool {
			return sessionOnly || lastRecord(rs, "authorize_command") != nil
		}), "authorize_command")
		if !sessionOnly && (resRec == nil || str(resRec, "verdict") != "permit") {
			fail("the command after resuming was not permitted: %s", recordCell(resRec))
		}
		if !res.printed {
			fail("show version after resuming printed no output: %s", res.cell(l.p.name))
		}

		// 8. Past the grace window: denied, and the context gone.
		sessionWaitUntil(t, p, expires2.Add(sessionGrace+10*time.Second), "the ceiling and the grace window, plus 10 s")
		offGone := l.mark()
		gone := runSessionStep(l.p.name, sh, "show version")
		goneRec := lastRecord(l.waitForRecords(offGone, 15*time.Second, func(rs []map[string]any) bool {
			return sessionOnly || lastRecord(rs, "authorize_command") != nil
		}), "authorize_command")
		if !sessionOnly && (goneRec == nil || str(goneRec, "reason") != "session_expired" ||
			!strings.HasPrefix(str(goneRec, "server_msg"), sessionEndedMsg)) {
			fail("the command past the grace window was not denied session_expired, session ended: %s", recordCell(goneRec))
		}
		p.at(t, "port49 refresh past the grace window")
		offLate := l.mark()
		late, _ := refreshCLI(sock)
		switch {
		case extendedTo.MatchString(late):
			fail("a refresh past the grace window extended the session: %q", late)
		case sessionOnly && !strings.Contains(late, "past the grace window"):
			// Nothing on Junos authorizes a command, so the refresh is the
			// first thing to find the context past its window.
			fail("on Junos the refresh past the grace window did not name the session past grace: %q", late)
		case !sessionOnly && strings.Contains(late, l.p.node+" ("):
			fail("the refresh past the grace window still found the context the command deleted: %q", late)
		}
		goneAgain := sessionStep{}
		goneAgainRec := map[string]any(nil)
		if !sessionOnly {
			goneAgain = runSessionStep(l.p.name, sh, "show version")
			goneAgainRec = lastRecord(l.waitForRecords(offLate, 15*time.Second, func(rs []map[string]any) bool {
				return lastRecord(rs, "authorize_command") != nil
			}), "authorize_command")
			if goneAgainRec == nil || str(goneAgainRec, "reason") != "context_missing" {
				fail("the context was not gone: the next command was %s", recordCell(goneAgainRec))
			}
		}
		lateRecs := sliceRecords(l.recordsSince(offLate), "refresh", "")

		// The notes. The whole transcript is searched too: a warning a device
		// printed after its prompt would be missed by the steps' own reads.
		whole := 0
		if sh != nil {
			whole = strings.Count(sh.c.transcript(), sessionWarning)
		}
		all := l.recordsSince(off)
		stopAgent()
		sessionCmdCell := func(s sessionStep, r map[string]any) string {
			if sessionOnly {
				return s.cell(l.p.name) + "; port49 was not asked (decision 21)"
			}
			return s.cell(l.p.name) + "; the record: " + recordCell(r)
		}
		junosNote := ""
		if sessionOnly {
			junosNote = "\n\nOn Junos the session reply at login is the one `server_msg` the device is ever sent " +
				"(decision 21): Junos authorizes no command with port49, so the command rows say only whether " +
				"`show version` ran, and the ceiling and the grace window are read off the refresh's answer " +
				"and the records.\n"
		}
		shown := func(b bool) string {
			if b {
				return "shown"
			}
			return "**not observed**"
		}
		permitted := func(s sessionStep) string {
			switch {
			case s.err != nil:
				return "**not observed**"
			case s.printed && !s.ended && !s.refused:
				return "still a permit: the output appeared and the session went on"
			}
			return "**not a permit**: " + s.cell(l.p.name)
		}
		l34Obs := fmt.Sprintf("Run at a 6m `max_session_age` with `session.ceiling_warning: 2m`; the login and the "+
			"command below came 4m10s after `port49 login`, inside the warning.\n\n"+
			"| What | The device | The record |\n|---|---|---|\n"+
			"| `port49 token` inside the warning | stderr: %s | — |\n"+
			"| login as `%s` (the session reply) | %s | %s |\n"+
			"| `show version` inside the warning (a per-command reply) | %s | %s |\n"+
			"| `port49 refresh` | exit %s | %d refresh record(s) |\n"+
			"| `show version` after the refresh | %s | %s |\n\n"+
			"**Session reply:** the warning %s; the login %s.\n\n"+
			"**Per-command reply:** %s.\n\n"+
			"The warning's text (`%s`) appears %d time(s) anywhere in the session's whole transcript, from login "+
			"to its last command. The transcript includes the reply to the paging command the harness types after "+
			"the first prompt (`terminal length 0`, or `set cli screen-length 0` on Junos), which a per-command "+
			"platform authorizes like any other command.\n\n"+
			"The refresh's output:\n\n```\n%s\n```\n%s",
			l29Cell(mintWarn), sliceUser, loginCell, recordCell(sessRec),
			inWarn.cell(l.p.name), map[bool]string{true: "port49 was not asked (decision 21)", false: recordCell(cmdRec)}[sessionOnly],
			map[bool]string{true: "0", false: "non-zero"}[refOK], len(refRecs),
			afterRef.cell(l.p.name), map[bool]string{true: "port49 was not asked (decision 21)", false: recordCell(afterRec)}[sessionOnly],
			shown(strings.Contains(preText, sessionWarning)),
			map[bool]string{true: "reached a prompt, so the reply was still a permit", false: "**did not reach a prompt**"}[loginErr == nil],
			map[bool]string{true: "not measurable on Junos: no per-command reply is ever sent (decision 21)",
				false: "the warning " + shown(inWarn.warned) + "; " + permitted(inWarn)}[sessionOnly],
			sessionWarning, whole, refreshed, junosNote)

		sessObs := fmt.Sprintf("Run at a 6m `max_session_age` (`%s`), `session.ceiling_warning: 2m`, "+
			"`session.grace_window: 2m`. `port49 login` at %s; the token's ceiling ran from the held connection's "+
			"handshake.\n\n"+
			"| Step | The device | The record |\n|---|---|---|\n"+
			"| 3. login inside the warning | %s | %s |\n"+
			"| 4. `show version` inside the warning | %s |\n"+
			"| 5. `port49 refresh`, then `show version` | refresh: %s; `show version`: %s |\n"+
			"| 6. `show version` at the ceiling + 10 s (%s) | %s |\n"+
			"| 7. `port49 refresh` inside the grace window, then `show version` | refresh: %s; `show version`: %s |\n"+
			"| 8. `show version` at the new ceiling + the grace window + 10 s (%s) | %s |\n"+
			"| 8. `port49 refresh` after it | %s; %d refresh record(s) |\n",
			sessionPolicyFile, l29Clock(loginAt),
			loginCell, recordCell(sessRec),
			sessionCmdCell(inWarn, cmdRec),
			l29Cell(refreshed), sessionCmdCell(afterRef, afterRec),
			l29Clock(expires.Add(10*time.Second)), sessionCmdCell(past, pastRec),
			l29Cell(resumed), sessionCmdCell(res, resRec),
			l29Clock(expires2.Add(sessionGrace+10*time.Second)), sessionCmdCell(gone, goneRec),
			l29Cell(late), len(lateRecs))
		if !sessionOnly {
			sessObs += fmt.Sprintf("| 8. `show version` once more | %s |\n", sessionCmdCell(goneAgain, goneAgainRec))
		}
		// The raw output goes beside the capture, so a note's quotes can be
		// checked against what the tool printed (Task 12 fix round 2).
		raw := filepath.Join("tests", "lab", "evidence", "session-refresh-"+l.p.name+".txt")
		rawText := fmt.Sprintf("# port49 refresh, as printed, in TestSessionLifetime on %s\n\n## step 5\n%s\n\n"+
			"## step 7\n%s\n\n## step 8\n%s\n", l.p.name, refreshed, resumed, late)
		if err := os.WriteFile(filepath.Join(root, raw), []byte(labcreds.RedactNote(rawText)), 0o644); err != nil {
			t.Errorf("write %s: %v", raw, err)
		}
		sessObs += fmt.Sprintf("\n`port49 refresh`'s output in full (raw: `%s`), at step 5:\n\n```\n%s\n```\n\n"+
			"At step 7:\n\n```\n%s\n```\n\nAt step 8:\n\n```\n%s\n```\n", raw, refreshed, resumed, late)
		sessObs += "\n**Not exercised here:** a nonce used twice, a challenge answered on another connection, the " +
			"10 s rate limit, and a refresh triggered by anything but an operator's `port49 refresh`. Those clauses " +
			"are unit-tested (plan 7b, Tasks 6–8); these notes are not evidence for them.\n"
		sessObs += fmt.Sprintf("\nRecords from `port49 login` on: %s.%s", l29Tally(sliceAll(all)), junosNote)
		sessObs += "\n" + l29Built() + "\n"
		if len(failed) > 0 {
			sessObs += "\n**Not as the claim says:**\n\n- " + strings.Join(failed, "\n- ") + "\n"
		}
		if sh != nil {
			sh.Close()
		}
		if !sessionOnly {
			// The session's accounting stop must be in the capture before a
			// note counts it (7a fix round 1, I1).
			offEnd := l.mark()
			l.waitForRecords(offEnd, 15*time.Second, func(rs []map[string]any) bool {
				return lastRecord(rs, "account") != nil
			})
		}
		l.result(t, "L34", l34Claim, l34Obs)
		l.result(t, "session", sessionClaim, sessObs)
		p.end()
		if len(failed) > 0 {
			t.Fatalf("%d step(s) not as claimed (the notes record them): %v", len(failed), failed)
		}
	})
}

// sliceAll are recs' records about slice01 or the slice's principal, any
// event.
func sliceAll(recs []map[string]any) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if str(sub(r, "session"), "username") == sliceUser || str(r, "principal") == slicePrincipal {
			out = append(out, r)
		}
	}
	return out
}

// lineWith is the first line of s containing sub, trimmed.
func lineWith(s, sub string) string {
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r", ""), "\n") {
		if strings.Contains(line, sub) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}
