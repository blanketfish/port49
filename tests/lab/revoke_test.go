//go:build lab

package lab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

const revokeClaim = "A revocation by principal or by certificate (`port49 revoke` over the admin socket, plan " +
	"7a; spec §5.1.4) reaches a live SSH session and everything behind it: on a platform that authorizes each " +
	"command the session's next command is refused and the session stays open; on Junos the open session keeps " +
	"what it had at login (spec §13 decision 21), and the revocation names it as not reached; a token minted " +
	"before the revocation and not yet spent is deleted, so its login is refused token_not_found; the revocation " +
	"closes the agent's held broker connection; the agent's next mint, on a new connection, is answered 401 " +
	"credential_revoked by the broker's listener as it binds, the agent ends on it, and a second `port49 token` " +
	"finds no agent; and after a lift a new login works."

// revokeRefusedLine is in the line port49d's listener writes when it
// refuses a revoked principal's or certificate's new connection as it binds.
const revokeRefusedLine = " as it bound"

// revokedMsg is the server_msg of an authorize_command deny
// credential_revoked (internal/daemon/author). IOS-XE prints a FAIL's
// server_msg and nothing else (tests/lab/results/slice-cisco_iosxe.md), so
// l29Refusals' `% Authorization failed.`, measured on an ERROR (L4), does
// not tell this refusal from output there.
const revokedMsg = "port49: this session was revoked"

// revokeOutcome is l29Outcome that also counts the device printing
// revokedMsg, the FAIL's own text, as a refusal.
func revokeOutcome(platform string, sh *labShell, cmd string, fail func(string, ...any), what string) string {
	out, took, ended, err := sh.runOrEnd(cmd, 60*time.Second)
	if err == nil && !ended && !l29Refused(platform, out) && strings.Contains(out, revokedMsg) {
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, revokedMsg) {
				return fmt.Sprintf("refused in %s: %s", took.Round(10*time.Millisecond), l29Cell(strings.TrimSpace(line)))
			}
		}
	}
	switch {
	case err != nil:
		fail("%s: not observed: %v", what, err)
		return "**not observed in 60s**: " + l29Cell(out)
	case ended:
		return fmt.Sprintf("the device ended the session after %s; it printed %s", took.Round(10*time.Millisecond),
			l29Cell(out))
	case l29Refused(platform, out):
		return fmt.Sprintf("refused in %s: %s", took.Round(10*time.Millisecond), l29Cell(l29RefusalLine(platform, out)))
	}
	return fmt.Sprintf("printed its output in %s: %s", took.Round(10*time.Millisecond), l29Cell(firstLine(out)))
}

// revokeCLI runs bin/port49 revoke with args against socket and returns
// its output and whether it exited 0.
func revokeCLI(socket string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(root, "bin", "port49"),
		append([]string{"revoke", "--socket", socket}, args...)...)
	// From the repository root, so a --cert path relative to it is what the
	// note quotes, not this machine's checkout.
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err == nil
}

// revokeAgent is l29Agent with the agent's pid: a revocation ends the
// agent on its own, and the run must see that it did (pre-flight I4).
// stop ends it only if it is still running.
func revokeAgent(t *testing.T) (sock string, pid int, stop func()) {
	t.Helper()
	pki := filepath.Join(root, slicePKIDir)
	dir, err := os.MkdirTemp("", "p49revoke")
	if err != nil {
		t.Fatal(err)
	}
	sock = filepath.Join(dir, "a", "agent.sock")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	out, err := exec.CommandContext(ctx, filepath.Join(root, "bin", "port49"), "login", "--broker", sliceBrokerURL,
		"--cert", filepath.Join(pki, testpki.LabClientCert), "--key", filepath.Join(pki, testpki.LabClientKey),
		"--broker-ca", filepath.Join(pki, testpki.LabCA), "--socket", sock).CombinedOutput()
	m := agentPID.FindSubmatch(out)
	if err != nil || m == nil {
		os.RemoveAll(dir)
		t.Fatalf("port49 login: %v\n%s", err, out)
	}
	pid, _ = strconv.Atoi(string(m[1]))
	return sock, pid, func() {
		if err := syscall.Kill(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
			t.Errorf("stopping the agent (pid %d): %v", pid, err)
		}
		os.RemoveAll(dir)
	}
}

// agentEnded waits up to 10 s for pid to exit.
func agentEnded(pid int) bool {
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return true
		}
	}
	return false
}

// redeemReason is the reason on the last redeem record for sliceUser with
// the token whose sha256 is sum, or "" for none.
func redeemReason(recs []map[string]any, sum string) string {
	reason := ""
	for _, r := range sliceRecords(recs, "redeem", "") {
		if str(sub(r, "auth"), "credential_sha256") == sum {
			reason = str(r, "reason")
		}
	}
	return reason
}

// mintRefusal says how a refused mint was refused, from what `port49
// token` printed: the broker's 401, or the listener closing the agent's new
// connection as it bound.
func mintRefusal(said string) string {
	switch {
	case strings.Contains(said, "credential_revoked"):
		return "a 401 credential_revoked"
	case strings.Contains(said, "the session is over") && strings.Contains(said, " was revoked at "):
		// The agent ended its session on the 401 and says why.
		return "a 401 credential_revoked, which ended the agent's session"
	case strings.Contains(said, "closed a new connection right after the handshake"):
		return "a new connection closed right after the handshake"
	}
	return "neither a 401 credential_revoked nor a closed connection"
}

// errLogSize is the size of port49d's stderr log, the offset its lines
// after now start at.
func (l *lab) errLogSize() int64 {
	fi, err := os.Stat(l.errPath)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// errLinesSince are port49d's stderr lines from off that contain s.
func (l *lab) errLinesSince(off int64, s string) []string {
	raw, err := os.ReadFile(l.errPath)
	if err != nil || int64(len(raw)) < off {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(raw[off:]), "\n") {
		if strings.Contains(line, s) {
			out = append(out, line)
		}
	}
	return out
}

// revokedMint asks the agent at sock (pid) for a token after a
// revocation, and checks what the claim says follows: the mint refused
// with a 401 credential_revoked, the agent ended on it, and a second
// `port49 token` finding no agent. It returns what the first said, whether
// the agent ended, and what the second said.
func revokedMint(sock string, pid int, device, what string, fail func(string, ...any)) (said string, gone bool, again string) {
	said, tok := l29Mint(sock, device)
	if tok != "" {
		fail("the agent minted a token after %s revocation", what)
	}
	if !strings.HasPrefix(mintRefusal(said), "a 401 credential_revoked") {
		fail("after %s revocation the agent's mint was refused with %s: %q", what, mintRefusal(said), said)
	}
	if gone = agentEnded(pid); !gone {
		fail("the agent (pid %d) was still running 10 s after %s revocation refused its mint (%s)", pid, what,
			mintRefusal(said))
	}
	again, tok = l29Mint(sock, device)
	if tok != "" || !strings.Contains(again, "no agent at") {
		fail("a second `port49 token` after %s revocation found an agent: %q (a token: %v)", what, again, tok != "")
	}
	return said, gone, again
}

func TestRevokeEndToEnd(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		var failed []string
		fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
		sessionOnly := strings.HasPrefix(l.p.name, "juniper_")

		pki := filepath.Join(root, slicePKIDir)
		if err := testpki.WriteLab(pki, sliceEmail, time.Now()); err != nil {
			t.Fatal(err)
		}
		brokerYAML, err := os.ReadFile(filepath.Join(root, "tests", "lab", "slice", "broker.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		socket := filepath.Join(root, "tests", "lab", "logs", "revoke-admin.sock")
		// The revocations file is rewritten into the derived config's private
		// directory, fresh at each start (privatePolicy; pre-flight I6).
		cfg, err := l.derivedConfig("revoke", platformSessionAttributes[l.p.name],
			string(brokerYAML)+"\nadmin_socket: "+socket+"\n")
		if err != nil {
			t.Fatal(err)
		}
		if err := l.stopDaemon(); err != nil {
			t.Fatal(err)
		}
		errOff := l.errLogSize()
		if err := l.startDaemonWith(cfg, true); err != nil {
			t.Fatalf("port49d would not start with the broker and the admin socket: %v", err)
		}
		if err := l.awaitTACACS(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := l.stopDaemon(); err != nil {
				t.Errorf("could not stop the revoke daemon: %v", err)
				return
			}
			std, err := l.configPath()
			if err != nil {
				t.Fatalf("derive this platform's daemon config: %v", err)
			}
			if err := l.startDaemonWith(std, true); err != nil {
				t.Fatalf("could not put port49d back on the lab config: %v", err)
			}
		}()
		stop := l.capture(t, "revoke")
		defer stop()
		off := l.mark()

		// 1. A live session, and an unspent token beside it.
		sock, pid, stopAgent := revokeAgent(t)
		defer stopAgent()
		_, tok1 := l29Mint(sock, l.p.node)
		said, tok2 := l29Mint(sock, l.p.node)
		if tok1 == "" || tok2 == "" {
			t.Fatalf("the agent minted no token before the revocation: %s", said)
		}
		sh, err := l.shell(sliceUser, tok1)
		if err != nil {
			t.Fatalf("SSH login with the first token: %v\nrecords:%s", err, summarize(l.recordsSince(off)))
		}
		defer sh.Close()
		before := revokeOutcome(l.p.name, sh, "show version", fail, "before the revocation")

		// 2. Revoke the principal.
		revokedText, revokedOK := revokeCLI(socket, "--principal", slicePrincipal)
		if !revokedOK {
			fail("port49 revoke --principal: %s", revokedText)
		}
		if sessionOnly != strings.Contains(revokedText, "not reached") {
			fail("the revocation's not-reached line: %q", revokedText)
		}
		after := revokeOutcome(l.p.name, sh, "show version", fail, "after the revocation")
		switch {
		case sessionOnly && !strings.HasPrefix(after, "printed its output"):
			fail("Junos: the open session did not keep what it had at login: %s", after)
		case !sessionOnly && !strings.HasPrefix(after, "refused"):
			fail("the next command was not refused: %s", after)
		}
		// The old token must be gone, not merely refused at the join: a
		// token the revocation failed to delete is refused credential_revoked
		// too, on this device, because its context is marked (pre-flight I5).
		if _, err := l.loginWithin(sliceUser, tok2, 60*time.Second, "show version"); err == nil {
			fail("the token minted before the revocation still logged in")
		}
		recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
			return redeemReason(rs, sha(tok2)) != ""
		})
		tok2Reason := redeemReason(recs, sha(tok2))
		if tok2Reason != "token_not_found" {
			fail("the old token's login was refused %q, not token_not_found: the token was not deleted", tok2Reason)
		}
		// The revocation closed the agent's held connection, so its next
		// mint dials anew; the listener answers that connection's request
		// 401 credential_revoked as it binds, and the agent ends.
		agentSaid, agentGone, agentAfter := revokedMint(sock, pid, l.p.node, "the principal's", fail)

		// 3. Lift, and a new login works.
		liftText, ok := revokeCLI(socket, "--lift", "--principal", slicePrincipal)
		if !ok {
			fail("port49 revoke --lift: %s", liftText)
		}
		sock2, pid2, stopAgent2 := revokeAgent(t)
		defer stopAgent2()
		_, tok4 := l29Mint(sock2, l.p.node)
		liftLogin := "no token"
		if tok4 != "" {
			if _, err := l.loginWithin(sliceUser, tok4, 150*time.Second, "show version"); err != nil {
				fail("a login after the lift: %v", err)
				liftLogin = "refused: " + err.Error()
			} else {
				liftLogin = "logged in and ran show version"
			}
		} else {
			fail("no token after the lift")
		}

		// 4. Revoke the certificate the agent holds: its next mint is refused,
		// and the agent ends.
		certText, ok := revokeCLI(socket, "--cert", filepath.Join(slicePKIDir, testpki.LabClientCert))
		if !ok {
			fail("port49 revoke --cert: %s", certText)
		}
		certSaid, agent2Gone, agent2After := revokedMint(sock2, pid2, l.p.node, "the certificate's", fail)
		certLift, ok := revokeCLI(socket, "--lift", "--cert", filepath.Join(slicePKIDir, testpki.LabClientCert))
		if !ok {
			fail("lifting the certificate: %s", certLift)
		}

		// The principal's revoke and lift name the principal; the
		// certificate's name none, so they are counted by event (M18).
		recs = l.waitForRecords(off, 60*time.Second, func(rs []map[string]any) bool {
			return len(sliceRecords(rs, "revoke", "")) >= 2
		})
		certRevokes := 0
		for _, r := range recs {
			if str(r, "event") == "revoke" && str(sub(r, "revocation"), "by") == "cert" {
				certRevokes++
			}
		}
		if len(sliceRecords(recs, "revoke", "credential_revoked")) == 0 {
			fail("no revoke record for the principal")
		}
		if certRevokes < 2 {
			fail("%d revoke records for the certificate, not its revocation and its lift", certRevokes)
		}
		if !sessionOnly && len(sliceRecords(recs, "authorize_command", "credential_revoked")) == 0 {
			fail("no authorize_command deny credential_revoked")
		}
		// Each refused mint is refused at the listener (a stderr line, at
		// most one per 10 s; a held one is counted on the next) or, a
		// connection that bound before the mark, at the mint (a record).
		refusedLines := l.errLinesSince(errOff, revokeRefusedLine)
		mintRevoked := len(sliceRecords(recs, "mint", "credential_revoked"))
		if len(refusedLines)+mintRevoked < 2 {
			fail("%d listener refusal lines and %d mint deny credential_revoked records, for two refused mints",
				len(refusedLines), mintRevoked)
		}
		gone := map[bool]string{true: "exited", false: "**kept running** (stopped by the test)"}
		obs := fmt.Sprintf("| Step | What happened |\n|---|---|\n"+
			"| `show version` before the revocation | %s |\n"+
			"| `port49 revoke --principal %s` | exit %s; report below |\n"+
			"| `show version` in the same session after it | %s |\n"+
			"| a login with a token minted before it, unspent | refused, `%s` |\n"+
			"| the agent's next mint | %s: %s; the agent %s; a second `port49 token`: %s |\n"+
			"| `port49 revoke --lift`, then a new agent, a mint and a login | %s |\n"+
			"| `port49 revoke --cert` (the agent's certificate), then the agent's mint | %s: %s; the agent %s; a "+
			"second `port49 token`: %s |\n\n"+
			"Records: %d revoke for the principal, %d for the certificate, %d authorize_command deny "+
			"credential_revoked, %d mint deny credential_revoked. port49d's stderr: %d line(s) of the listener "+
			"closing a revoked connection as it bound (at most one per 10 s; later ones are counted on the next).\n\n"+
			"The principal's revocation report, as `port49 revoke` printed it:\n\n```\n%s\n```\n\n"+
			"The certificate's:\n\n```\n%s\n```\n",
			before, slicePrincipal, map[bool]string{true: "0", false: "non-zero"}[revokedOK],
			after, tok2Reason, mintRefusal(agentSaid), l29Cell(agentSaid), gone[agentGone], l29Cell(agentAfter), liftLogin,
			mintRefusal(certSaid), l29Cell(certSaid), gone[agent2Gone], l29Cell(agent2After),
			len(sliceRecords(recs, "revoke", "")), certRevokes,
			len(sliceRecords(recs, "authorize_command", "credential_revoked")), mintRevoked, len(refusedLines),
			revokedText, certText)
		if len(failed) > 0 {
			obs += "\n**Not as the claim says:**\n\n- " + strings.Join(failed, "\n- ") + "\n"
		}
		l.result(t, "revoke", revokeClaim, obs)
		if len(failed) > 0 {
			t.Fatalf("%d step(s) not as claimed (the note records them): %v\nrecords:%s", len(failed), failed, summarize(recs))
		}
	})
}
