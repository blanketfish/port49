//go:build lab

package lab

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const l41Claim = "On the compose deployment (plan 7f; port49d, port49-broker and three etcd members as containers), an " +
	"idle port49d whose store hangs closes its TACACS+ listener within close_after × interval + call_timeout " +
	"(5.5s at the defaults; the bound allows 5s more for the poll), and break-glass then logs in; an open " +
	"session's next command once it is closed is recorded beside the same command with port49d stopped; once the " +
	"store returns, port49d says its open_after passes before it listens again, and the session's next command " +
	"the device sends it is answered from the context the store kept (policy engine spec §13 decision 37)."

func TestL41GoDarkMidSession(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		var failed []string
		fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
		sessionOnly := strings.HasPrefix(l.p.name, "juniper_")
		var obs strings.Builder
		wide := func(cell, what string) { fmt.Fprintf(&obs, "| %s | %s |\n", cell, wideCell(what)) }
		obs.WriteString("| cell | observed |\n|---|---|\n")

		c := l.startCompose(t)
		stop := l.capture(t, "L41")
		defer stop()
		capPath := filepath.Join(root, "tests", "lab", "captures", "L41-"+l.p.name+".pcap")
		times := func(from, to time.Time) string {
			l.flushCapture(t)
			as, err := splitAttempts(capPath, l.p.addr, from, to)
			conns := renderAttempts(as)
			if err != nil {
				conns = "capture unreadable: " + err.Error()
			}
			return strings.Join(replyTimesFrom(capPath, labKeyDefault, from, to, true), "; ") + " | connections: " + conns
		}
		// waitLine is how long after `from` the line s appears on port49d's
		// stderr past off, or 0 if it does not within `within` of from. Each
		// call measures from the moment its caller names, never from its own
		// start: a second wait that begins after the first returned would
		// otherwise read near 0 for a line that was already there.
		waitLine := func(off int64, s string, within time.Duration, from time.Time) time.Duration {
			for time.Since(from) < within {
				if len(l.errLinesSince(off, s)) > 0 {
					return time.Since(from)
				}
				time.Sleep(250 * time.Millisecond)
			}
			return 0
		}

		// 1. The baseline: a login, `show version` permitted, its ctx_id.
		off := l.mark()
		sock, _, stopAgent := revokeAgent(t)
		defer stopAgent()
		said, tok := l29Mint(sock, l.p.node)
		if tok == "" {
			t.Fatalf("the agent minted no token through the compose broker: %s", said)
		}
		sh, err := l.shell(sliceUser, tok)
		if err != nil {
			t.Fatalf("SSH login: %v", err)
		}
		defer sh.Close()
		from := time.Now()
		before := storeOutcome(l.p.name, sh, "show version", fail, "baseline")
		ctx1, v1, r1 := ctxIDOf(l.waitForRecords(off, 30*time.Second, hasCtx(sessionOnly)), sliceUser)
		wide("1. login through the compose port49d, `show version`", fmt.Sprintf("%s; record %s %s, ctx_id %s | %s",
			before, v1, r1, ctx1, times(from, time.Now())))

		// 2. The store hangs; no device asks. When port49d closes.
		errOff := l.errLogSize()
		if err := c.HangStore(); err != nil {
			t.Fatal(err)
		}
		hungAt := time.Now()
		dark := waitLine(errOff, "closing every listener so that devices use their local method", 60*time.Second, hungAt)
		bound := healthDarkBound(labHealthInterval, labCallTimeout, labCloseAfter)
		wide("2. the store hangs (the three members paused), no device asking: port49d closes its listener",
			fmt.Sprintf("%s after the hang (bound %s); the line: %s", dark.Round(100*time.Millisecond), bound,
				firstOf(l.errLinesSince(errOff, "consecutive store health checks failed"))))
		if dark == 0 || dark > bound {
			fail("port49d closed its listener %s after the hang, bound %s", dark, bound)
		}

		// 3. The open session's next command, the listener closed.
		time.Sleep(3 * time.Second) // the drain
		from = time.Now()
		out3 := shellCell(l, sh, "show version")
		wide("3. listener closed: the open session's `show version`", out3+" | "+times(from, time.Now()))

		// 4. Break-glass, the listener closed.
		from = time.Now()
		outs, berr := l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version")
		wide("4. listener closed: break-glass and `show version`", fmt.Sprintf("login err %v in %s; printed %s | %s",
			berr, time.Since(from).Round(100*time.Millisecond), firstOut(outs), times(from, time.Now())))
		if berr != nil {
			fail("break-glass did not log in with the listener closed: %v", berr)
		}

		// 5. The store returns: the passes, then the listener.
		errOff = l.errLogSize()
		if err := c.ReleaseStore(); err != nil {
			t.Fatal(err)
		}
		releaseAt := time.Now() // both times below are measured from the release
		passed := waitLine(errOff, fmt.Sprintf("%d consecutive health checks passed", labOpenAfter), 120*time.Second, releaseAt)
		listening := waitLine(errOff, "listening on", 120*time.Second, releaseAt)
		if err := l.awaitTACACS(); err != nil {
			fail("TACACS+ did not answer again: %v", err)
		}
		wide("5. the store returns: the passes said, then listening", fmt.Sprintf("passes said %s, listening %s after the release",
			passed.Round(100*time.Millisecond), listening.Round(100*time.Millisecond)))
		if passed == 0 || listening == 0 {
			fail("after the store returned: passes said %s, listening %s", passed, listening)
		}

		// 6. When the device asks port49d again: the open session's
		// `show version` every 5s, up to 5 minutes, until port49d records
		// it (Junos: no command is sent, decision 21; a fresh login is
		// measured instead).
		off = l.mark()
		back := time.Now()
		var asked time.Duration
		var ctx6, v6, r6 string
		neverAsked := false // a device that does not ask again within 5 minutes: recorded, the row stays open for it
		if sessionOnly {
			said, tok2 := l29Mint(sock, l.p.node)
			if tok2 == "" {
				t.Fatalf("no token after the return: %s", said)
			}
			_, lerr := l.loginWithin(sliceUser, tok2, 90*time.Second, "show version")
			asked = time.Since(back)
			wide("6. Junos: a fresh login after the return (an open session's command sends no TACACS+)",
				fmt.Sprintf("err %v, %s after listening | %s", lerr, asked.Round(100*time.Millisecond), times(back, time.Now())))
			if lerr != nil {
				fail("a fresh login after the store returned: %v", lerr)
			}
		} else {
			for time.Since(back) < 5*time.Minute {
				shellCell(l, sh, "show version")
				ctx6, v6, r6 = ctxIDOf(l.recordsSince(off), sliceUser)
				if ctx6 != "" {
					asked = time.Since(back)
					break
				}
				time.Sleep(5 * time.Second)
			}
			wide("6. the open session's `show version` until port49d is asked again", fmt.Sprintf(
				"asked %s after listening; record %s %s, ctx_id %s (before: %s) | %s", asked.Round(100*time.Millisecond),
				v6, r6, ctx6, ctx1, times(back, time.Now())))
			switch {
			case ctx6 == "":
				// What the device did, not a defect of port49d: no command
				// reached it in 5 minutes. Recorded, and the row stays open
				// for this platform (CLAUDE.md, register rule 3).
				neverAsked = true
			case v6 != "permit" || ctx6 != ctx1:
				fail("after the return the session was not answered from its kept context: %s %s %s/%s", v6, r6, ctx6, ctx1)
			}
		}

		// 7. Beside port49d stopped: the same command, and break-glass.
		if err := c.StopDaemon(); err != nil {
			t.Fatal(err)
		}
		from = time.Now()
		out7 := shellCell(l, sh, "show version")
		wide("7. port49d stopped: the open session's `show version`", out7+" | "+times(from, time.Now()))
		from = time.Now()
		outs7, berr7 := l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version")
		wide("7. port49d stopped: break-glass", fmt.Sprintf("login err %v in %s; printed %s",
			berr7, time.Since(from).Round(100*time.Millisecond), firstOut(outs7)))
		if err := c.StartDaemon(); err != nil {
			t.Fatal(err)
		}
		wide("3 beside 7", fmt.Sprintf("closed on its checks: %s; stopped: %s", firstLine(out3), firstLine(out7)))

		note := obs.String()
		if neverAsked {
			note += "\n**Cell 6 is not measured on this platform:** the device did not ask port49d again within 5 " +
				"minutes of its listening. That is what the device did, recorded; L41 stays open for " + l.p.name + ".\n"
		}
		if len(failed) > 0 {
			note += "\n**Not as the claim says:**\n\n- " + strings.Join(failed, "\n- ") + "\n"
		}
		l.result(t, "L41", l41Claim, note)
		if len(failed) > 0 {
			t.Fatalf("L41 on %s: %s", l.p.name, strings.Join(failed, "; "))
		}
	})
}

// firstOf is the first of lines, or "none".
func firstOf(lines []string) string {
	if len(lines) == 0 {
		return "none"
	}
	return lines[0]
}
