//go:build lab

package lab

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

const (
	oncallEmail = "bob@slice.port49.test"
	peerEmail   = "carol@slice.port49.test"
)

const apiRevokeClaim = "The HTTP revocation (`POST /v1/tokens/revoke`, plan 7c; spec §5.1.4, §13 decision 34) reaches " +
	"a live SSH session as the admin socket's does, under the caller's api: rights: a peer with no right who names " +
	"the operator is refused 403 api_right_missing and the operator's next command still runs; the operator's " +
	"`port49 revoke --mine` refuses the open session's next command on a platform that authorizes each command (Junos " +
	"keeps what it had at login and the report names it), refuses the unspent token token_not_found, and leaves no " +
	"mark, so a token minted after it logs in at once, and that login re-admits the session the revocation refused, " +
	"whose next command runs again (decision 15's join; the report says to close such a session first); a peer's key " +
	"revocation without the right is refused 403 as well; an on-call holding revoke_others ends the operator's session by " +
	"(device, username) with no mark, and the operator logs in again at once; and the on-call's revocation of the " +
	"principal is a standing mark with the on-call as its origin, which ends the operator's agent until a lift."

func TestAPIRevokeEndToEnd(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		var failed []string
		fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
		sessionOnly := strings.HasPrefix(l.p.name, "juniper_")

		pki := filepath.Join(root, slicePKIDir)
		if err := testpki.WriteLabWith(pki, sliceEmail, []string{oncallEmail, peerEmail}, time.Now()); err != nil {
			t.Fatal(err)
		}
		brokerYAML, err := os.ReadFile(filepath.Join(root, "tests", "lab", "slice", "broker.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		brokerYAML = []byte(strings.Replace(string(brokerYAML), "tests/lab/slice/policy.yaml",
			"tests/lab/slice/api-policy.yaml", 1))
		socket := filepath.Join(root, "tests", "lab", "logs", "api-revoke-admin.sock")
		cfg, err := l.derivedConfig("api-revoke", platformSessionAttributes[l.p.name],
			string(brokerYAML)+"\nadmin_socket: "+socket+"\n")
		if err != nil {
			t.Fatal(err)
		}
		if err := l.stopDaemon(); err != nil {
			t.Fatal(err)
		}
		if err := l.startDaemonWith(cfg, true); err != nil {
			t.Fatalf("port49d would not start with the broker and the admin socket: %v", err)
		}
		if err := l.awaitTACACS(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := l.stopDaemon(); err != nil {
				t.Errorf("could not stop the api-revoke daemon: %v", err)
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
		stop := l.capture(t, "api-revoke")
		defer stop()
		off := l.mark()

		aliceSock, alicePID, stopAlice := personAgent(t, testpki.LabClientCert, testpki.LabClientKey)
		defer stopAlice()
		bobCert, bobKey := testpki.LabClientFiles(oncallEmail)
		bobSock, _, stopBob := personAgent(t, bobCert, bobKey)
		defer stopBob()
		carolCert, carolKey := testpki.LabClientFiles(peerEmail)
		carolSock, _, stopCarol := personAgent(t, carolCert, carolKey)
		defer stopCarol()

		// 1. A live session, and an unspent token beside it.
		_, tok1 := l29Mint(aliceSock, l.p.node)
		_, tok2 := l29Mint(aliceSock, l.p.node)
		if tok1 == "" || tok2 == "" {
			t.Fatal("alice's agent minted no token")
		}
		sh, err := l.shell(sliceUser, tok1)
		if err != nil {
			t.Fatalf("SSH login: %v\nrecords:%s", err, summarize(l.recordsSince(off)))
		}
		defer sh.Close()

		// 2. The peer, with no right, names alice: refused, and her session goes on.
		peerText, peerCode := agentRevoke(carolSock, "--via-agent", "--principal", slicePrincipal)
		if peerCode != 1 || !strings.Contains(peerText, "needs the api: revoke_others right") {
			fail("the peer's revocation of alice: exit %d: %s", peerCode, peerText)
		}
		// The key form without the right is refused too, never answered as
		// carol's own sessions there (pre-flight I2).
		peerKeyText, peerKeyCode := agentRevoke(carolSock, "--via-agent", "--device", l.p.node, "--username", sliceUser)
		if peerKeyCode != 1 || !strings.Contains(peerKeyText, "needs the api: revoke_others right") {
			fail("the peer's key revocation: exit %d: %s", peerKeyCode, peerKeyText)
		}
		afterPeer := revokeOutcome(l.p.name, sh, "show version", fail, "after the peer's refused revocations")
		if !strings.HasPrefix(afterPeer, "printed its output") {
			fail("alice's session after the peer's refused revocations: %s", afterPeer)
		}

		// 3. alice ends her own sessions.
		mineText, mineCode := agentRevoke(aliceSock, "--mine")
		if mineCode != 0 || !strings.Contains(mineText, "nothing stands against "+slicePrincipal) ||
			!strings.Contains(mineText, "close their session on the device") {
			fail("revoke --mine: exit %d: %s", mineCode, mineText)
		}
		if sessionOnly != strings.Contains(mineText, "not reached") {
			fail("revoke --mine's report and the platform disagree on reach: %s", mineText)
		}
		afterMine := revokeOutcome(l.p.name, sh, "show version", fail, "after revoke --mine")
		switch {
		case sessionOnly && !strings.HasPrefix(afterMine, "printed its output"):
			fail("Junos: the open session did not keep what it had at login: %s", afterMine)
		case !sessionOnly && !strings.HasPrefix(afterMine, "refused"):
			fail("the next command after revoke --mine was not refused: %s", afterMine)
		}
		if _, err := l.loginWithin(sliceUser, tok2, 60*time.Second, "show version"); err == nil {
			fail("the token minted before revoke --mine still logged in")
		}
		recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
			return redeemReason(rs, sha(tok2)) != ""
		})
		tok2Reason := redeemReason(recs, sha(tok2))
		if tok2Reason != "token_not_found" {
			fail("the old token's login was refused %q, not token_not_found", tok2Reason)
		}
		if agentEnded(alicePID) {
			fail("alice's agent ended on a self-revocation, which leaves no mark")
		}
		_, tok3 := l29Mint(aliceSock, l.p.node)
		sh3, err := l.shell(sliceUser, tok3)
		reLogin := "logged in"
		if err != nil {
			fail("a login with a token minted after revoke --mine: %v", err)
			reLogin = "refused: " + err.Error()
		} else {
			defer sh3.Close()
			if out := revokeOutcome(l.p.name, sh3, "show version", fail, "on the new login"); !strings.HasPrefix(out, "printed its output") {
				fail("the new login's command: %s", out)
			}
		}
		// The new login joined the context the old session shares and lifted its
		// mark (decision 15): the session --mine refused runs again. This is what
		// the report's second line warns of (pre-flight I1); recorded as found.
		afterReLogin := revokeOutcome(l.p.name, sh, "show version", fail, "the old session after the re-login")
		if !strings.HasPrefix(afterReLogin, "printed its output") {
			fail("the session --mine refused did not run again after the re-login (decision 15's join): %s", afterReLogin)
		}

		// 4. The on-call ends alice's session on this device by key.
		keyText, keyCode := agentRevoke(bobSock, "--via-agent", "--device", l.p.node, "--username", sliceUser)
		if keyCode != 0 || !strings.Contains(keyText, "ended the session on "+l.p.node+" ("+sliceUser+")") {
			fail("the on-call's key revocation: exit %d: %s", keyCode, keyText)
		}
		if sh3 != nil {
			afterKey := revokeOutcome(l.p.name, sh3, "show version", fail, "after the key revocation")
			if !sessionOnly && !strings.HasPrefix(afterKey, "refused") {
				fail("the next command after the on-call's key revocation was not refused: %s", afterKey)
			}
		}
		_, tok4 := l29Mint(aliceSock, l.p.node)
		afterKeyLogin := "logged in and ran show version"
		if _, err := l.loginWithin(sliceUser, tok4, 150*time.Second, "show version"); err != nil {
			fail("a login after the key revocation: %v", err)
			afterKeyLogin = "refused: " + err.Error()
		}

		// 5. The on-call revokes the principal: a standing mark, his origin.
		markText, markCode := agentRevoke(bobSock, "--via-agent", "--principal", slicePrincipal)
		if markCode != 0 || !strings.Contains(markText, "every mint by "+slicePrincipal+" is refused") {
			fail("the on-call's revocation of alice: exit %d: %s", markCode, markText)
		}
		listText, _ := revokeCLI(socket, "--list")
		if !strings.Contains(listText, "(api user:"+oncallEmail+")") {
			fail("port49 revoke --list does not name the on-call as the origin: %s", listText)
		}
		agentSaid, agentGone, _ := revokedMint(aliceSock, alicePID, l.p.node, "the principal's", fail)
		liftText, ok := revokeCLI(socket, "--lift", "--principal", slicePrincipal)
		if !ok {
			fail("the lift on the admin socket: %s", liftText)
		}
		sock2, _, stopAlice2 := personAgent(t, testpki.LabClientCert, testpki.LabClientKey)
		defer stopAlice2()
		_, tok5 := l29Mint(sock2, l.p.node)
		liftLogin := "logged in and ran show version"
		if _, err := l.loginWithin(sliceUser, tok5, 150*time.Second, "show version"); err != nil {
			fail("a login after the lift: %v", err)
			liftLogin = "refused: " + err.Error()
		}

		recs = l.waitForRecords(off, 60*time.Second, func(rs []map[string]any) bool {
			return len(sliceRecords(rs, "revoke", "")) >= 6
		})
		bys := map[string]int{}
		for _, r := range recs {
			if str(r, "event") == "revoke" {
				bys[str(sub(r, "revocation"), "by")+" "+str(r, "reason")]++
			}
		}
		for _, want := range []string{"principal api_right_missing", "key api_right_missing", "self credential_revoked",
			"key credential_revoked", "principal credential_revoked", "principal revocation_lifted"} {
			if bys[want] == 0 {
				fail("no revoke record %q: %v", want, bys)
			}
		}
		gone := map[bool]string{true: "exited", false: "**kept running** (stopped by the test)"}
		obs := fmt.Sprintf("| Step | What happened |\n|---|---|\n"+
			"| carol (no right): `port49 revoke --via-agent --principal %s` | exit %d: %s |\n"+
			"| carol (no right): `--via-agent --device %s --username %s` | exit %d: %s |\n"+
			"| alice's `show version` after both | %s |\n"+
			"| alice: `port49 revoke --mine` | exit %d; report below |\n"+
			"| alice's `show version` in the same session after it | %s |\n"+
			"| a login with a token minted before it, unspent | refused, `%s` |\n"+
			"| a login with a token minted after it | %s |\n"+
			"| the session `--mine` refused, after that login | %s |\n"+
			"| bob (revoke_others): `--via-agent --device %s --username %s` | exit %d; report below |\n"+
			"| a login after the key revocation | %s |\n"+
			"| bob: `--via-agent --principal %s` | exit %d; `--list` names `api user:%s` |\n"+
			"| alice's agent's next mint | %s: %s; the agent %s |\n"+
			"| a lift on the admin socket, a new agent, a mint and a login | %s |\n\n"+
			"Revoke records by `by` and reason: %v.\n\n"+
			"`port49 revoke --mine` printed:\n\n```\n%s\n```\n\n"+
			"The key revocation:\n\n```\n%s\n```\n\n"+
			"The principal's:\n\n```\n%s\n```\n",
			slicePrincipal, peerCode, l29Cell(peerText), l.p.node, sliceUser, peerKeyCode, l29Cell(peerKeyText), afterPeer,
			mineCode, afterMine, tok2Reason, reLogin, afterReLogin,
			l.p.node, sliceUser, keyCode, afterKeyLogin, slicePrincipal, markCode, oncallEmail,
			mintRefusal(agentSaid), l29Cell(agentSaid), gone[agentGone], liftLogin, bys, mineText, keyText, markText)
		if len(failed) > 0 {
			obs += "\n**Not as the claim says:**\n\n- " + strings.Join(failed, "\n- ") + "\n"
		}
		// Closing the sessions sends their accounting stops on the per-command
		// platforms; they must be in the capture before the note counts them
		// (TestRevokeEndToEnd's fix round 1, I1).
		offEnd := l.mark()
		sh.Close()
		if sh3 != nil {
			sh3.Close()
		}
		if !sessionOnly {
			l.waitForRecords(offEnd, 15*time.Second, func(rs []map[string]any) bool {
				for _, r := range rs {
					if str(r, "event") == "account" && str(sub(r, "session"), "username") == sliceUser {
						return true
					}
				}
				return false
			})
		}
		l.result(t, "api-revoke", apiRevokeClaim, obs)
		if len(failed) > 0 {
			t.Fatalf("%d step(s) not as claimed (the note records them): %v\nrecords:%s", len(failed), failed, summarize(recs))
		}
	})
}
