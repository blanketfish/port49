//go:build lab

package lab

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// The split deployment (plan 7e): port49-broker and two port49d replicas on
// one etcd, the device listing both replicas as TACACS+ servers (startSplit).
// L37 is its slice, L38 the IOS-XE open session with port49 unreachable, L36
// the Junos re-authorization after a replica restarts.

const splitClaim = "On the split deployment (port49-broker and two port49d replicas on one etcd, the device " +
	"listing both replicas as TACACS+ servers): a session opened through one replica has its next command " +
	"answered by the other once the first stops; with the broker stopped an open session runs on and a token " +
	"minted before the stop logs in; a revocation made on port49-broker denies the session's next command on " +
	"either replica; and a port49d with no hold closes its listeners within seconds of its store hanging, " +
	"after which the device takes break-glass (plan 7e; spec §13 decision 36)."

const iosxeOpenClaim = "On IOS-XE, an open session's `show privilege` and `show version`, typed once both port49d " +
	"replicas are unreachable, are answered as L4's reading 3 says (the device's local method) whether or not " +
	"the session's last command was answered FAIL store_unavailable, and the device sends port49 nothing " +
	"(plan 7e; compare quarantine-cisco_iosxe.md)."

const junosReauthClaim = "On Junos with `tacplus-options authorization-time-interval 15`, an open session is " +
	"re-authorized by the device after the port49d replica it logged in through restarts on etcd, and after " +
	"the principal is revoked the next re-authorization is denied; what the device does with the session on a " +
	"denial is recorded (plan 7e; spec §13 decision 21)."

// shellBody is a command's output without its echo (the first line) and the
// prompt and blank lines after it.
func shellBody(node, out string) string {
	lines := strings.Split(strings.ReplaceAll(out, "\r", ""), "\n")
	if len(lines) > 0 {
		lines = lines[1:]
	}
	for len(lines) > 0 && (strings.TrimSpace(lines[len(lines)-1]) == "" ||
		strings.Contains(lines[len(lines)-1], node)) {
		lines = lines[:len(lines)-1]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// shellCell says what cmd printed in sh, for a table cell: how long it took,
// whether the session ended, and the output's size and first line.
func shellCell(l *lab, sh *labShell, cmd string) string {
	out, took, ended, err := sh.runOrEnd(cmd, 60*time.Second)
	d := took.Round(10 * time.Millisecond)
	body := shellBody(l.hostName(), out)
	switch {
	case err != nil:
		return fmt.Sprintf("**not observed in 60s**: %s", l29Cell(body))
	case ended:
		return fmt.Sprintf("the device ended the session after %s; it printed %s", d, l29Cell(body))
	case body == "":
		return fmt.Sprintf("nothing, prompt back in %s", d)
	}
	return fmt.Sprintf("%d bytes in %s, first line %s", len(body), d, l29Cell(firstLine(body)))
}

// countOf is how many of list equal s.
func countOf(list []string, s string) int {
	n := 0
	for _, x := range list {
		if x == s {
			n++
		}
	}
	return n
}

// waitRecordsOf is waitForRecords for any decision log.
func waitRecordsOf(path string, off int64, timeout time.Duration, want func([]map[string]any) bool) []map[string]any {
	deadline := time.Now().Add(timeout)
	for {
		recs := recordsAt(path, off)
		if want(recs) || !time.Now().Before(deadline) {
			return recs
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// hasCtx is a wait condition: a record carries sliceUser's context, or, on
// Junos, which authorizes no command and so has no context to carry, an
// accounting record has arrived (they arrive after the command, so a wait
// that is true at once would read the log before the record is there).
func hasCtx(sessionOnly bool) func([]map[string]any) bool {
	return func(rs []map[string]any) bool {
		if sessionOnly {
			return len(reasonsOf(rs, "account")) > 0
		}
		id, _, _ := ctxIDOf(rs, sliceUser)
		return id != ""
	}
}

func TestSplitEndToEnd(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		var failed []string
		fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
		sessionOnly := strings.HasPrefix(l.p.name, "juniper_")
		var obs strings.Builder
		wide := func(cell, what string) { fmt.Fprintf(&obs, "| %s | %s |\n", cell, wideCell(what)) }
		obs.WriteString("| cell | observed |\n|---|---|\n")

		s := l.startSplit(t, splitCfg{SecondServer: true})
		stop := l.capture(t, "L37")
		defer stop()
		capPath := filepath.Join(root, "tests", "lab", "captures", "L37-"+l.p.name+".pcap")
		errA, errB := l.errLogSize(), s.B.errSize()
		wide("0. the device's TACACS+ servers, read back after the push", s.Readback)

		// triedB says whether the device opened a connection to B in a window:
		// a cell on "B" in which it did not measured the device's local method.
		triedB := func(from, to time.Time) bool {
			l.flushCapture(t)
			as, _ := splitAttempts(capPath, l.p.addr, from, to)
			for _, a := range as {
				if a.Server == splitSecondAddr {
					return true
				}
			}
			return false
		}

		// times is a cell's request-to-reply times from the capture, each with
		// the server that replied, and the connections the device opened: the
		// device's delay before it tried the other server is the second
		// connection's offset (pre-flight I17, as L35's cells).
		times := func(from, to time.Time) string {
			l.flushCapture(t)
			as, err := splitAttempts(capPath, l.p.addr, from, to)
			conns := renderAttempts(as)
			if err != nil {
				conns = "capture unreadable: " + err.Error()
			}
			return strings.Join(replyTimesFrom(capPath, labKeyDefault, from, to, true), "; ") + " | connections: " + conns
		}

		// 1. The baseline. B is stopped, so the login is A's.
		if err := s.StopB(); err != nil {
			t.Fatal(err)
		}
		offA := l.mark()
		sock, _, stopAgent := revokeAgent(t)
		defer stopAgent()
		said, tok1 := l29Mint(sock, l.p.node)
		if tok1 == "" {
			t.Fatalf("the agent minted no token through port49-broker: %s", said)
		}
		from := time.Now()
		sh, err := l.shell(sliceUser, tok1)
		if err != nil {
			t.Fatalf("SSH login through A: %v\nrecords:%s", err, summarize(l.recordsSince(offA)))
		}
		defer sh.Close()
		before := storeOutcome(l.p.name, sh, "show version", fail, "baseline")
		ctx1, v1, r1 := ctxIDOf(l.waitForRecords(offA, 30*time.Second, hasCtx(sessionOnly)), sliceUser)
		if !strings.HasPrefix(before, "printed its output") {
			fail("show version did not run in the baseline: %s", before)
		}
		if !sessionOnly && ctx1 == "" {
			fail("A's record of the baseline command carried no ctx_id within 30s: cell 2 cannot compare B's with it")
		}
		if err := s.StartB(); err != nil {
			t.Fatal(err)
		}
		wide("1. mint through port49-broker, log in through A (B stopped, started after), `show version`",
			fmt.Sprintf("%s; A's record %s %s, ctx_id %s | %s", before, v1, r1, ctx1, times(from, time.Now())))

		// 2. A stops. The session's next command goes to B, if the device
		// tries it. A cell in which the device never tried B measured no
		// failover: it is measured again, up to storeAttempts times (Ruling
		// T15-a), and then recorded as what the device did.
		tried := false
		for attempt := 1; attempt <= storeAttempts && !tried; attempt++ {
			var cellFailed []string
			offB := s.B.mark()
			if err := s.StopA(); err != nil {
				t.Fatal(err)
			}
			from = time.Now()
			out := storeOutcome(l.p.name, sh, "show version", func(f string, a ...any) {
				cellFailed = append(cellFailed, fmt.Sprintf(f, a...))
			}, "with A stopped")
			to := time.Now()
			recsB := waitRecordsOf(s.B.logPath, offB, 30*time.Second, hasCtx(sessionOnly))
			ctxB, vB, rB := ctxIDOf(recsB, sliceUser)
			tm := times(from, to)
			as, _ := splitAttempts(capPath, l.p.addr, from, to)
			for _, a := range as {
				tried = tried || a.Server == splitSecondAddr
			}
			label := fmt.Sprintf("2. A stopped, the open session's `show version` (attempt %d)", attempt)
			if !tried {
				wide(label, "INVALID: the device never connected to B; measured again. "+out+" | "+tm)
			} else {
				wide(label, fmt.Sprintf("%s; B's record %s %s, ctx_id %s (A's before: %s) | %s", out, vB, rB, ctxB, ctx1, tm))
				failed = append(failed, cellFailed...)
				if !sessionOnly && (!strings.HasPrefix(out, "printed its output") || vB != "permit" || ctxB != ctx1) {
					fail("B did not answer the session A wrote: %s; record %s %s, ctx_id %s, before %s", out, vB, rB, ctxB, ctx1)
				}
				if sessionOnly && len(reasonsOf(recsB, "account")) == 0 {
					fail("no accounting record reached B for the Junos session after A stopped: %s", out)
				}
			}
			if !tried && attempt < storeAttempts {
				if err := s.StartA(); err != nil {
					t.Fatal(err)
				}
			}
		}
		if !tried {
			wide("2. validity", fmt.Sprintf("INVALID for closing (L37 stays open on this image): on all %d attempts the device "+
				"never connected to B with A stopped. That is the device's behaviour, a device fact and not a port49 "+
				"defect, and the readback in row 0 shows B listed after A, so it was configured. The cell is valid "+
				"when the device tries B: a device that does not needs a second server it will try, or this row "+
				"is measured with a different command method.", storeAttempts))
		}

		// 3. A is back; the broker stops. The session's next command, then a
		// token minted before the stop.
		if err := s.StartA(); err != nil {
			t.Fatal(err)
		}
		said, tok2 := l29Mint(sock, l.p.node)
		if tok2 == "" {
			t.Fatalf("the agent minted no token before the broker stopped: %s", said)
		}
		if err := s.StopBroker(); err != nil {
			t.Fatal(err)
		}
		offA = l.mark()
		from = time.Now()
		out3 := storeOutcome(l.p.name, sh, "show version", fail, "with the broker stopped")
		ctx3, v3, r3 := ctxIDOf(l.waitForRecords(offA, 30*time.Second, hasCtx(sessionOnly)), sliceUser)
		_, lerr := l.loginWithin(sliceUser, tok2, 90*time.Second, "show version")
		recs3 := l.waitForRecords(offA, 30*time.Second, func(rs []map[string]any) bool { return redeemReason(rs, sha(tok2)) != "" })
		redeem3 := redeemReason(recs3, sha(tok2))
		wide("3. A started, the broker stopped: the open session's `show version`, then a login with a token minted before the stop",
			fmt.Sprintf("%s; record %s %s, ctx_id %s (before: %s); the login: err %v, redeem %q | %s", out3, v3, r3, ctx3,
				ctx1, lerr, redeem3, times(from, time.Now())))
		if !strings.HasPrefix(out3, "printed its output") {
			fail("the open session's next command did not run with the broker stopped: %s", out3)
		}
		if !sessionOnly && (v3 != "permit" || ctx3 != ctx1) {
			fail("with the broker stopped the next command was not answered from the kept context: %s %s %s/%s", v3, r3, ctx3, ctx1)
		}
		if lerr != nil || redeem3 != "token_redeemed" {
			fail("the token minted before the broker stopped did not log in: err %v, redeem %q", lerr, redeem3)
		}

		// 4. The broker returns; a revocation on it reaches the session on A,
		// then, with A stopped, on B (if the device tries B: the B half is
		// measured again, up to storeAttempts times, the revocation standing).
		// Junos authorizes no command (decision 21), so there is no command to
		// deny: the revocation's reach is measured by a login through B with
		// a token minted before it.
		if err := s.StartBroker(); err != nil {
			t.Fatal(err)
		}
		tok3 := ""
		if sessionOnly {
			said, tok3 = l29Mint(sock, l.p.node)
			if tok3 == "" {
				t.Fatalf("the agent minted no token before the revocation: %s", said)
			}
		}
		revText, revOK := revokeCLI(s.AdminBroker, "--principal", slicePrincipal)
		if !revOK {
			fail("port49 revoke --principal on the broker's socket: %s", revText)
		}
		wide("4. `port49 revoke --principal` on the broker's socket", firstLine(revText))
		if sessionOnly {
			wide("4. the session's next command", "not applicable: Junos authorizes no command (decision 21); the "+
				"revocation's reach on the session is L36's, and its reach on a login through B is measured here")
			if err := s.StopA(); err != nil {
				t.Fatal(err)
			}
			reached := false
			for attempt := 1; attempt <= storeAttempts && !reached; attempt++ {
				offB := s.B.mark()
				fromB := time.Now()
				_, lerr := l.loginWithin(sliceUser, tok3, 90*time.Second, "show version")
				recsB := waitRecordsOf(s.B.logPath, offB, 30*time.Second, func(rs []map[string]any) bool { return redeemReason(rs, sha(tok3)) != "" })
				redeemB := redeemReason(recsB, sha(tok3))
				reached = triedB(fromB, time.Now())
				label := fmt.Sprintf("4. A stopped, a login through B with a token minted before the revocation (attempt %d)", attempt)
				if !reached {
					wide(label, "INVALID: the device never connected to B; measured again | "+times(fromB, time.Now()))
					continue
				}
				wide(label, fmt.Sprintf("login err %v; B's redeem reason %q | %s", lerr, redeemB, times(fromB, time.Now())))
				if lerr == nil {
					fail("a token minted before the revocation logged in through B")
				}
			}
			if !reached {
				wide("4. validity", fmt.Sprintf("INVALID for closing (L37 stays open on this image): on all %d attempts the device "+
					"never connected to B", storeAttempts))
			}
			if err := s.StartA(); err != nil {
				t.Fatal(err)
			}
		} else {
			offA, offB := l.mark(), s.B.mark()
			from = time.Now()
			outA := revokeOutcome(l.p.name, sh, "show version", fail, "on A after the revocation")
			recsA := l.waitForRecords(offA, 30*time.Second, func(rs []map[string]any) bool { return len(reasonsOf(rs, "authorize_command")) > 0 })
			wide("4. the session's next command on A", fmt.Sprintf("%s; records %v | %s", outA, reasonsOf(recsA, "authorize_command"), times(from, time.Now())))
			if !strings.HasPrefix(outA, "refused") || !contains(reasonsOf(recsA, "authorize_command"), "deny credential_revoked") {
				fail("the revocation did not deny the session's next command on A: %s %v", outA, reasonsOf(recsA, "authorize_command"))
			}
			if err := s.StopA(); err != nil {
				t.Fatal(err)
			}
			reached := false
			for attempt := 1; attempt <= storeAttempts && !reached; attempt++ {
				var cellFailed []string
				fromB := time.Now()
				outB := revokeOutcome(l.p.name, sh, "show version", func(f string, a ...any) {
					cellFailed = append(cellFailed, fmt.Sprintf(f, a...))
				}, "on B after the revocation")
				recsB := waitRecordsOf(s.B.logPath, offB, 30*time.Second, func(rs []map[string]any) bool { return len(reasonsOf(rs, "authorize_command")) > 0 })
				reached = triedB(fromB, time.Now())
				label := fmt.Sprintf("4. A stopped, the session's next command on B (attempt %d)", attempt)
				if !reached {
					wide(label, "INVALID: the device never connected to B; measured again. "+outB+" | "+times(fromB, time.Now()))
					continue
				}
				wide(label, fmt.Sprintf("%s; records %v | %s", outB, reasonsOf(recsB, "authorize_command"), times(fromB, time.Now())))
				failed = append(failed, cellFailed...)
				if !strings.HasPrefix(outB, "refused") || !contains(reasonsOf(recsB, "authorize_command"), "deny credential_revoked") {
					fail("the revocation did not deny the session's next command on B: %s %v", outB, reasonsOf(recsB, "authorize_command"))
				}
			}
			if !reached {
				wide("4. validity", fmt.Sprintf("INVALID for closing (L37 stays open on this image): on all %d attempts the device "+
					"never connected to B with A stopped, so the revocation's reach on B is unmeasured; a device fact, "+
					"not a port49 defect (row 0 shows B listed)", storeAttempts))
			}
			if err := s.StartA(); err != nil {
				t.Fatal(err)
			}
		}
		if lines := l.errLinesSince(errA, "closing every listener"); len(lines) > 0 {
			fail("A closed its listeners during cells 1 to 4: %s", lines[0])
		}
		if lines := s.B.errLinesSince(errB, "closing every listener"); len(lines) > 0 {
			fail("B closed its listeners during cells 1 to 4: %s", lines[0])
		}

		// 5. Lift; the store hangs. Neither port49d holds a hold, so each goes
		// dark on its own probe. Break-glass logs in once both are.
		liftText, liftOK := revokeCLI(s.AdminBroker, "--lift", "--principal", slicePrincipal)
		if !liftOK {
			fail("port49 revoke --lift: %s", liftText)
		}
		errA, errB = l.errLogSize(), s.B.errSize()
		s.Proxy.Hang(true)
		hungAt := time.Now()
		// The wait runs to 180s so the observed time is always written; each
		// port49d's go-dark is judged against the configuration's bound
		// (darkBound, 125.5s at 5 pings, 60s, 500ms).
		dts := waitDark(hungAt, 180*time.Second,
			func(sub string) bool { return len(l.errLinesSince(errA, sub)) > 0 },
			func(sub string) bool { return len(s.B.errLinesSince(errB, sub)) > 0 })
		wide("5. the store hangs: when each port49d's circuit opened and it closed its listeners", fmt.Sprintf("A: %s; B: %s; bound %s",
			dts[0].describe(), dts[1].describe(), darkBound(labHoldTTL, labCallTimeout, labBreakerFailures)))
		failed = append(failed, dts[0].verdict("A")...)
		failed = append(failed, dts[1].verdict("B")...)
		time.Sleep(5 * time.Second) // the drain
		from = time.Now()
		outs, berr := l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version")
		wide("5. both listeners closed, break-glass and `show version`", fmt.Sprintf("login err %v in %s; printed %s | %s",
			berr, time.Since(from).Round(100*time.Millisecond), firstOut(outs), times(from, time.Now())))
		if berr != nil {
			fail("break-glass did not log in with both listeners closed: %v", berr)
		}
		s.Proxy.Hang(false)
		if err := l.listenAgain(errA, 150*time.Second); err != nil {
			fail("A did not listen again after the store returned: %v", err)
		}
		if err := s.ListenAgainB(errB, 150*time.Second); err != nil {
			fail("B did not listen again after the store returned: %v", err)
		}

		note := obs.String()
		if len(failed) > 0 {
			note += "\n**Not as the claim says:**\n\n- " + strings.Join(failed, "\n- ") + "\n"
		}
		l.result(t, "L37", splitClaim, note)
		if len(failed) > 0 {
			t.Fatalf("L37 on %s: %s", l.p.name, strings.Join(failed, "; "))
		}
	})
}

func TestIOSXEOpenSessionUnreachable(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "cisco_iosxe" {
			t.Skip("L38 is measured on IOS-XE alone")
		}
		var failed []string
		fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
		var obs strings.Builder
		obs.WriteString("| cell | typed first in its session | typed second in its session |\n|---|---|---|\n")

		s := l.startSplit(t, splitCfg{SecondServer: true})
		stop := l.capture(t, "L38")
		defer stop()
		capPath := filepath.Join(root, "tests", "lab", "captures", "L38-"+l.p.name+".pcap")
		sock, _, stopAgent := revokeAgent(t)
		defer stopAgent()

		wide := func(cell, what string) { fmt.Fprintf(&obs, "| %s | %s |\n", cell, wideCell(what)) }
		wide("0. the device's TACACS+ servers, read back after the push", s.Readback+" | |")

		cmds := []string{"show privilege", "show version"}
		// column measures one column: two fresh sessions opened while every
		// process answers, the store hung and `show clock` typed in each when
		// failFirst, then both daemons stopped and each session typing both
		// commands, a window and a capture count per command. It returns
		// the rows, and why the column is invalid, if it is.
		column := func(failFirst bool, col string) (rows []string, invalid string) {
			var shs []*labShell
			defer func() {
				for _, sh := range shs {
					sh.Close()
				}
			}()
			open := func() *labShell {
				said, tok := l29Mint(sock, l.p.node)
				if tok == "" {
					t.Fatalf("the agent minted no token for %s: %s", col, said)
				}
				sh, err := l.shell(sliceUser, tok)
				if err != nil {
					t.Fatalf("SSH login for %s: %v", col, err)
				}
				return sh
			}
			// The session's privilege level, in a session of its own so that
			// the two measured sessions type nothing else (the quarantine
			// session this is compared with ran at priv 15).
			probe := open()
			priv := shellCell(l, probe, "show privilege")
			probe.Close()
			rows = append(rows, fmt.Sprintf("| (a separate session's `show privilege` while every process answers) | %s | |", l29Cell(priv)))
			// Two sessions: the first will type show privilege and then
			// show version, the second the reverse, so an order effect is
			// told from a command effect.
			for i := 0; i < 2; i++ {
				shs = append(shs, open())
			}
			if failFirst {
				// `show clock`, which neither measured command is, with the
				// store hung: it must be answered FAIL store_unavailable, in
				// the decision log and on the wire, in both sessions, or the
				// column is not "after a FAIL" (IOS-XE prints nothing for it, L4).
				offA := l.mark()
				s.Proxy.Hang(true)
				from := time.Now()
				for i, sh := range shs {
					rows = append(rows, fmt.Sprintf("| (the FAIL, session %d: `show clock` with the store hung) | %s | |", i+1,
						wideCell(shellCell(l, sh, "show clock"))))
				}
				recs := l.waitForRecords(offA, 30*time.Second, func(rs []map[string]any) bool {
					return countOf(reasonsOf(rs, "authorize_command"), "deny store_unavailable") >= 2
				})
				l.flushCapture(t)
				replies := replyTimesFrom(capPath, labKeyDefault, from, time.Now(), true)
				got := countOf(reasonsOf(recs, "authorize_command"), "deny store_unavailable")
				onWire := repliesWith(replies, "FAIL", "172.100.100.1")
				rows = append(rows, fmt.Sprintf("| (the FAIL's proof) | %d deny store_unavailable record(s) on A; %d AUTHOR FAIL(s) on the wire: %s | |",
					got, onWire, l29Cell(strings.Join(replies, "; "))))
				if got < 2 || onWire < 2 {
					invalid = fmt.Sprintf("the FAIL store_unavailable was not answered to both sessions (%d record(s), %d FAIL(s) on the wire)", got, onWire)
				}
			}
			if err := s.StopB(); err != nil {
				t.Fatal(err)
			}
			if err := s.StopA(); err != nil {
				t.Fatal(err)
			}
			got := map[string][2]string{} // command → [typed first, typed second]
			for i, sh := range shs {
				order := []string{cmds[i], cmds[1-i]}
				for pos, cmd := range order {
					from := time.Now()
					cell := shellCell(l, sh, cmd)
					to := time.Now()
					l.flushCapture(t)
					syns, data, err := splitSent(capPath, l.p.addr, from, to)
					sent := fmt.Sprintf("the device sent port49 %d connection(s) and %d packet(s) with a payload", syns, data)
					if err != nil {
						sent = "capture unreadable: " + err.Error()
						fail("the capture could not be read for %s: %v", col, err)
					} else if as, err := splitAttempts(capPath, l.p.addr, from, to); err == nil && len(as) > 0 {
						sent += ": " + renderAttempts(as)
					}
					v := got[cmd]
					v[pos] = fmt.Sprintf("session %d: %s; %s", i+1, cell, sent)
					got[cmd] = v
				}
			}
			for _, cmd := range cmds {
				rows = append(rows, fmt.Sprintf("| `%s`, %s | %s | %s |", cmd, col, wideCell(got[cmd][0]), wideCell(got[cmd][1])))
			}
			return rows, invalid
		}
		restart := func() {
			s.Proxy.Hang(false)
			if err := s.StartA(); err != nil {
				t.Fatal(err)
			}
			if err := s.StartB(); err != nil {
				t.Fatal(err)
			}
		}
		for _, failFirst := range []bool{false, true} {
			col := "the daemons stopped after a permit (the harness's `terminal length 0`)"
			if failFirst {
				col = "the daemons stopped after a FAIL store_unavailable on the session's last command"
			}
			// A column whose FAIL did not happen measured the permit column
			// under the wrong label: it is measured again on fresh sessions,
			// up to storeAttempts times (Ruling T15-a), then left INVALID.
			for attempt := 1; attempt <= storeAttempts; attempt++ {
				rows, invalid := column(failFirst, col)
				restart()
				fmt.Fprintf(&obs, "| (%s, attempt %d) | | |\n", col, attempt)
				for _, r := range rows {
					obs.WriteString(r + "\n")
				}
				if invalid == "" {
					break
				}
				fmt.Fprintf(&obs, "| INVALID for closing (L38 stays open): %s | | |\n", invalid)
				if attempt == storeAttempts {
					fail("%s: INVALID on all %d attempts: %s", col, storeAttempts, invalid)
				}
			}
		}
		obs.WriteString("\nThe harness's first command in every session, `terminal length 0`, was permitted by port49 before " +
			"the daemons stopped, so the first column is \"after a permit\", not \"after nothing\".\n")
		note := obs.String()
		if len(failed) > 0 {
			note += "\n**Not as the claim says:**\n\n- " + strings.Join(failed, "\n- ") + "\n"
		}
		l.result(t, "L38", iosxeOpenClaim, note)
		if len(failed) > 0 {
			t.Fatalf("L38 on %s: %s", l.p.name, strings.Join(failed, "; "))
		}
	})
}

// authorRequestsAfter are the AUTHOR requests the device sent after from, in
// the capture at path.
func authorRequestsAfter(path string, from time.Time) []wirePacket {
	pkts, _, err := pcapTACACSPackets(path, labKeyDefault)
	if err != nil {
		return nil
	}
	var out []wirePacket
	for _, p := range pkts {
		if p.FromDevice && p.Header.Type == wire.TypeAuthor && p.Header.SeqNo == 1 && p.At.After(from) {
			out = append(out, p)
		}
	}
	return out
}

// reauth is how a wait for the device's next re-authorization ended: Req is
// the request's time; Ended, when the session ended first; Dead, when an
// SSH keepalive went unanswered first (the transport, not the device's
// reaction); none of them when d passed.
type reauth struct {
	Req, Ended, Dead time.Time
	DeadErr          error
}

// awaitReauthorization waits until the device has sent an AUTHOR request after
// from, up to d, watching the open session too: every 15s it reads the
// capture and the session, and every 60s it sends an SSH keepalive with a 10s
// reply deadline, so that a dropped transport is told from the device's own
// reaction to a denial (Task 17 review I-7).
func awaitReauthorization(t *testing.T, l *lab, sh *labShell, path string, from time.Time, d time.Duration) reauth {
	t.Helper()
	lastKeepalive := time.Now()
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(15 * time.Second) {
		l.flushCapture(t)
		if ps := authorRequestsAfter(path, from); len(ps) > 0 {
			return reauth{Req: ps[0].At}
		}
		if sh.ended() {
			return reauth{Ended: time.Now()}
		}
		if sh.c.keepalive != nil && time.Since(lastKeepalive) >= 60*time.Second {
			lastKeepalive = time.Now()
			if err := sh.c.keepalive(10 * time.Second); err != nil {
				return reauth{Dead: time.Now(), DeadErr: err}
			}
		}
	}
	return reauth{}
}

// watchSessionEnd waits up to d for the session to end, and says whether it
// did and when.
func watchSessionEnd(sh *labShell, d time.Duration) (time.Time, bool) {
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(2 * time.Second) {
		if sh.ended() {
			return time.Now(), true
		}
	}
	return time.Time{}, false
}

func TestJunosReauthorizationAfterRestart(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if !strings.HasPrefix(l.p.name, "juniper_") {
			t.Skip("L36 is measured on the Junos images")
		}
		var failed []string
		fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
		var obs strings.Builder
		wide := func(step, what string) { fmt.Fprintf(&obs, "| %s | %s |\n", step, wideCell(what)) }
		obs.WriteString("| step | observed |\n|---|---|\n")

		s := l.startSplit(t, splitCfg{SecondServer: true})
		const interval = "set system tacplus-options authorization-time-interval 15"
		s.configureDevice(t, []string{interval})
		// Registered after the split's own cleanup, so it runs before it: the
		// interval is taken off the device while both replicas can be stopped.
		t.Cleanup(func() {
			s.configureDevice(t, []string{"delete system tacplus-options authorization-time-interval"})
		})
		stop := l.capture(t, "L36")
		defer stop()
		capPath := filepath.Join(root, "tests", "lab", "captures", "L36-"+l.p.name+".pcap")
		wide("0. the device's TACACS+ servers, read back after the push", s.Readback)

		// Log in through A with B stopped, so the device asks A, and keep the
		// session.
		if err := s.StopB(); err != nil {
			t.Fatal(err)
		}
		sock, _, stopAgent := revokeAgent(t)
		defer stopAgent()
		said, tok := l29Mint(sock, l.p.node)
		if tok == "" {
			t.Fatalf("the agent minted no token: %s", said)
		}
		offA := l.mark()
		loginAt := time.Now()
		sh, err := l.shell(sliceUser, tok)
		if err != nil {
			t.Fatalf("SSH login through A: %v\nrecords:%s", err, summarize(l.recordsSince(offA)))
		}
		defer sh.Close()
		wide("1. `"+interval+"`, a login through A (B stopped)", fmt.Sprintf("logged in; `show version`: %s",
			shellCell(l, sh, "show version")))

		// Restart A: the device's next re-authorization finds a daemon that
		// started after the session did.
		if err := s.StopA(); err != nil {
			t.Fatal(err)
		}
		if err := s.StartA(); err != nil {
			t.Fatal(err)
		}
		restartAt := time.Now()
		offA = l.mark()
		w := awaitReauthorization(t, l, sh, capPath, restartAt, 20*time.Minute)
		switch {
		case !w.Req.IsZero():
			reply := replyTimesFrom(capPath, labKeyDefault, w.Req.Add(-time.Second), w.Req.Add(30*time.Second), true)
			wide("2. A restarted; the first re-authorization request", fmt.Sprintf("%s after the login, %s after the restart: %s",
				w.Req.Sub(loginAt).Round(time.Second), w.Req.Sub(restartAt).Round(time.Second), strings.Join(reply, "; ")))
			if repliesWith(reply, "PASS_ADD", "172.100.100.1")+repliesWith(reply, "PASS_REPL", "172.100.100.1") == 0 {
				fail("the re-authorization after A's restart was not answered PASS from 172.100.100.1: %s", strings.Join(reply, "; "))
			}
		case !w.Dead.IsZero():
			wide("2. A restarted; the session", fmt.Sprintf("INVALID: the SSH transport died %s after the login (%v) with no re-authorization request",
				w.Dead.Sub(loginAt).Round(time.Second), w.DeadErr))
			fail("the SSH transport died before a re-authorization request: %v", w.DeadErr)
		case !w.Ended.IsZero():
			wide("2. A restarted; the session", fmt.Sprintf("INVALID: the session ended %s after the login with no re-authorization request and no denial",
				w.Ended.Sub(loginAt).Round(time.Second)))
			fail("the session ended before a re-authorization request")
		default:
			wide("2. A restarted; the first re-authorization request", "INVALID: none within 20 minutes of the restart")
			fail("no re-authorization request within 20 minutes of the restart (the session was open %s)",
				time.Since(loginAt).Round(time.Second))
		}
		recs := l.waitForRecords(offA, 30*time.Second, func(rs []map[string]any) bool { return len(reasonsOf(rs, "authorize_session")) > 0 })
		wide("2. port49d A's records since the restart", fmt.Sprintf("authorize_session %v; accounting %v", reasonsOf(recs, "authorize_session"),
			reasonsOf(recs, "account")))
		if !w.Req.IsZero() && !anyPrefix(reasonsOf(recs, "authorize_session"), "permit") {
			fail("A's records show no permit for the re-authorization after its restart: %v", reasonsOf(recs, "authorize_session"))
		}
		wide("2. the session after the re-authorization, `show version`", shellCell(l, sh, "show version"))

		// Revoke the principal and wait for the next re-authorization.
		revText, revOK := revokeCLI(s.AdminBroker, "--principal", slicePrincipal)
		if !revOK {
			fail("port49 revoke --principal: %s", revText)
		}
		revokeAt := time.Now()
		offA = l.mark()
		wide("3. `port49 revoke --principal` on the broker's socket", firstLine(revText))
		w2 := awaitReauthorization(t, l, sh, capPath, revokeAt, 20*time.Minute)
		var denied bool
		switch {
		case !w2.Req.IsZero():
			reply := replyTimesFrom(capPath, labKeyDefault, w2.Req.Add(-time.Second), w2.Req.Add(30*time.Second), true)
			wide("3. the next re-authorization request", fmt.Sprintf("%s after the revocation: %s",
				w2.Req.Sub(revokeAt).Round(time.Second), strings.Join(reply, "; ")))
			denied = repliesWith(reply, "FAIL", "172.100.100.1")+repliesWith(reply, "ERROR", "172.100.100.1") > 0
			if !denied {
				fail("the re-authorization after the revocation was not denied: %s", strings.Join(reply, "; "))
			}
		case !w2.Dead.IsZero():
			wide("3. the session", fmt.Sprintf("INVALID: the SSH transport died %s after the revocation (%v) before a re-authorization request",
				w2.Dead.Sub(revokeAt).Round(time.Second), w2.DeadErr))
			fail("the SSH transport died before the re-authorization after the revocation: %v", w2.DeadErr)
		case !w2.Ended.IsZero():
			wide("3. the session", fmt.Sprintf("INVALID: ended %s after the revocation with no re-authorization request before it",
				w2.Ended.Sub(revokeAt).Round(time.Second)))
			fail("the session ended after the revocation with no re-authorization request and no denial before it")
		default:
			wide("3. the next re-authorization request", "INVALID: none within 20 minutes of the revocation")
			fail("no re-authorization request within 20 minutes of the revocation")
		}
		recs = l.waitForRecords(offA, 30*time.Second, func(rs []map[string]any) bool { return len(reasonsOf(rs, "authorize_session")) > 0 })
		wide("3. port49d A's records since the revocation", fmt.Sprintf("authorize_session %v", reasonsOf(recs, "authorize_session")))
		if denied && !contains(reasonsOf(recs, "authorize_session"), "deny credential_revoked") {
			fail("A's records show no deny credential_revoked for the re-authorization after the revocation: %v", reasonsOf(recs, "authorize_session"))
		}
		// What the device does with the session on a denial: watched for 60s,
		// and an end is the denial's only if a FAIL or ERROR reached the
		// device within 60s before it.
		if endAt, ended := watchSessionEnd(sh, 60*time.Second); ended {
			l.flushCapture(t)
			if denialBefore(authorReplies(capPath, revokeAt), endAt, 60*time.Second) {
				wide("3. the session after the denial", fmt.Sprintf("the device ended the session %s after the revocation, with a FAIL or ERROR before it",
					endAt.Sub(revokeAt).Round(time.Second)))
			} else {
				wide("3. the session after the denial", "INVALID: the session ended with no denial before it")
				fail("the session ended with no FAIL or ERROR to the device in the 60s before it")
			}
		} else {
			wide("3. the session after the denial", "still open 60s after the denial; `show version`: "+shellCell(l, sh, "show version"))
		}

		note := obs.String()
		if len(failed) > 0 {
			note += "\n**Not as the claim says:**\n\n- " + strings.Join(failed, "\n- ") + "\n"
		}
		l.result(t, "L36", junosReauthClaim, note)
		if len(failed) > 0 {
			t.Fatalf("L36 on %s: %s", l.p.name, strings.Join(failed, "; "))
		}
	})
}

// anyPrefix reports whether any of list starts with prefix.
func anyPrefix(list []string, prefix string) bool {
	for _, x := range list {
		if strings.HasPrefix(x, prefix) {
			return true
		}
	}
	return false
}
