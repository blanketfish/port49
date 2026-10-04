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

// hasCtx is a wait condition: a record carries sliceUser's context, or the
// platform has none to carry (Junos authorizes locally).
func hasCtx(sessionOnly bool) func([]map[string]any) bool {
	return func(rs []map[string]any) bool {
		id, _, _ := ctxIDOf(rs, sliceUser)
		return id != "" || sessionOnly
	}
}

func TestSplitEndToEnd(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		var failed []string
		fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
		sessionOnly := strings.HasPrefix(l.p.name, "juniper_")
		var obs strings.Builder
		row := func(cell, what string) { fmt.Fprintf(&obs, "| %s | %s |\n", cell, l29Cell(what)) }
		wide := func(cell, what string) { fmt.Fprintf(&obs, "| %s | %s |\n", cell, wideCell(what)) }
		obs.WriteString("| cell | observed |\n|---|---|\n")

		s := l.startSplit(t, splitCfg{SecondServer: true})
		stop := l.capture(t, "L37")
		defer stop()
		capPath := filepath.Join(root, "tests", "lab", "captures", "L37-"+l.p.name+".pcap")
		errA, errB := l.errLogSize(), s.B.errSize()

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
				if sessionOnly && len(recsB) == 0 {
					fail("no record reached B for the Junos session after A stopped: %s", out)
				}
			}
			if !tried && attempt < storeAttempts {
				if err := s.StartA(); err != nil {
					t.Fatal(err)
				}
			}
		}
		if !tried {
			row("2. validity", fmt.Sprintf("INVALID on all %d attempts: the device never connected to B with A stopped; "+
				"if that holds on every attempt it is the device's behaviour (it tries no second server), a device fact, not a defect", storeAttempts))
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
		// then, with A stopped, on B.
		if err := s.StartBroker(); err != nil {
			t.Fatal(err)
		}
		revText, revOK := revokeCLI(s.AdminBroker, "--principal", slicePrincipal)
		if !revOK {
			fail("port49 revoke --principal on the broker's socket: %s", revText)
		}
		offA, offB := l.mark(), s.B.mark()
		from = time.Now()
		outA := revokeOutcome(l.p.name, sh, "show version", fail, "on A after the revocation")
		recsA := l.waitForRecords(offA, 30*time.Second, func(rs []map[string]any) bool { return len(reasonsOf(rs, "authorize_command")) > 0 || sessionOnly })
		toA := time.Now()
		timesA := times(from, toA)
		if err := s.StopA(); err != nil {
			t.Fatal(err)
		}
		fromB := time.Now()
		outB := revokeOutcome(l.p.name, sh, "show version", fail, "on B after the revocation")
		recsB := waitRecordsOf(s.B.logPath, offB, 30*time.Second, func(rs []map[string]any) bool { return len(reasonsOf(rs, "authorize_command")) > 0 || sessionOnly })
		timesB := times(fromB, time.Now())
		if err := s.StartA(); err != nil {
			t.Fatal(err)
		}
		wide("4. `port49 revoke --principal` on the broker's socket", firstLine(revText))
		wide("4. the session's next command on A", fmt.Sprintf("%s; records %v | %s", outA, reasonsOf(recsA, "authorize_command"), timesA))
		wide("4. A stopped, the session's next command on B", fmt.Sprintf("%s; records %v | %s", outB, reasonsOf(recsB, "authorize_command"), timesB))
		if !sessionOnly {
			if !strings.HasPrefix(outA, "refused") || !contains(reasonsOf(recsA, "authorize_command"), "deny credential_revoked") {
				fail("the revocation did not deny the session's next command on A: %s %v", outA, reasonsOf(recsA, "authorize_command"))
			}
			if !strings.HasPrefix(outB, "refused") || !contains(reasonsOf(recsB, "authorize_command"), "deny credential_revoked") {
				fail("the revocation did not deny the session's next command on B: %s %v", outB, reasonsOf(recsB, "authorize_command"))
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
		var darkA, darkB time.Duration
		for time.Since(hungAt) < 180*time.Second && (darkA == 0 || darkB == 0) {
			if darkA == 0 && len(l.errLinesSince(errA, "closing every listener")) > 0 {
				darkA = time.Since(hungAt)
			}
			if darkB == 0 && len(s.B.errLinesSince(errB, "closing every listener")) > 0 {
				darkB = time.Since(hungAt)
			}
			time.Sleep(250 * time.Millisecond)
		}
		wide("5. the store hangs: seconds to each port49d closing its listeners", fmt.Sprintf("A %s (%v), B %s (%v); "+
			"A: %s / B: %s", darkA.Round(100*time.Millisecond), darkA > 0, darkB.Round(100*time.Millisecond), darkB > 0,
			strings.Join(l.errLinesSince(errA, "closing every listener"), " "),
			strings.Join(s.B.errLinesSince(errB, "closing every listener"), " ")))
		if darkA == 0 || darkB == 0 {
			fail("a port49d did not close its listeners within 180s of the hang: A %v, B %v", darkA > 0, darkB > 0)
		}
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
		obs.WriteString("| cell | first in its session | second in its session | the device sent port49 |\n|---|---|---|---|\n")

		s := l.startSplit(t, splitCfg{SecondServer: true})
		stop := l.capture(t, "L38")
		defer stop()
		capPath := filepath.Join(root, "tests", "lab", "captures", "L38-"+l.p.name+".pcap")
		sock, _, stopAgent := revokeAgent(t)
		defer stopAgent()

		cmds := []string{"show privilege", "show version"}
		for _, failFirst := range []bool{false, true} {
			col := "the daemons stopped with nothing before"
			if failFirst {
				col = "the daemons stopped after a FAIL store_unavailable on the session's last command"
			}
			// Two sessions, opened while everything answers: the first will
			// type show privilege and then show version, the second the
			// reverse, so an order effect is told from a command effect.
			var shs []*labShell
			for i := 0; i < 2; i++ {
				said, tok := l29Mint(sock, l.p.node)
				if tok == "" {
					t.Fatalf("the agent minted no token for %s: %s", col, said)
				}
				sh, err := l.shell(sliceUser, tok)
				if err != nil {
					t.Fatalf("SSH login for %s: %v", col, err)
				}
				defer sh.Close()
				shs = append(shs, sh)
			}
			if failFirst {
				// `show clock`, which neither measured command is, with the
				// store hung: answered FAIL store_unavailable, and the
				// session's last command. IOS-XE prints nothing for it (L4).
				s.Proxy.Hang(true)
				for i, sh := range shs {
					fmt.Fprintf(&obs, "| (the FAIL, session %d: `show clock` with the store hung) | %s | | |\n", i+1,
						shellCell(l, sh, "show clock"))
				}
			}
			if err := s.StopB(); err != nil {
				t.Fatal(err)
			}
			if err := s.StopA(); err != nil {
				t.Fatal(err)
			}
			from := time.Now()
			got := map[string][2]string{} // command → [first, second]
			for i, sh := range shs {
				order := []string{cmds[i], cmds[1-i]}
				for pos, cmd := range order {
					v := got[cmd]
					v[pos] = fmt.Sprintf("session %d: %s", i+1, shellCell(l, sh, cmd))
					got[cmd] = v
				}
			}
			to := time.Now()
			l.flushCapture(t)
			syns, data, err := splitSent(capPath, l.p.addr, from, to)
			sent := fmt.Sprintf("%d connection(s) opened, %d packet(s) with a payload", syns, data)
			if err != nil {
				sent = "capture unreadable: " + err.Error()
				fail("the capture could not be read for %s: %v", col, err)
			}
			for _, cmd := range cmds {
				fmt.Fprintf(&obs, "| `%s`, %s | %s | %s | %s |\n", cmd, col, got[cmd][0], got[cmd][1], sent)
			}
			s.Proxy.Hang(false)
			for _, sh := range shs {
				sh.Close()
			}
			if err := s.StartA(); err != nil {
				t.Fatal(err)
			}
			if err := s.StartB(); err != nil {
				t.Fatal(err)
			}
		}
		obs.WriteString("\nThe harness's first command in every session, `terminal length 0`, was permitted by port49 before " +
			"the daemons stopped: \"nothing before\" is nothing but that.\n")
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

// awaitReauthorization waits until the device has sent an AUTHOR request after
// from, up to d, watching the open session too: it returns the request's
// time, and when the session ended, if it did first. A wait that ends with
// neither returns the zero time.
func awaitReauthorization(t *testing.T, l *lab, sh *labShell, path string, from time.Time, d time.Duration) (req, ended time.Time) {
	t.Helper()
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(15 * time.Second) {
		l.flushCapture(t)
		if ps := authorRequestsAfter(path, from); len(ps) > 0 {
			return ps[0].At, time.Time{}
		}
		if sh.ended() {
			return time.Time{}, time.Now()
		}
	}
	return time.Time{}, time.Time{}
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
		req, ended := awaitReauthorization(t, l, sh, capPath, restartAt, 20*time.Minute)
		switch {
		case !req.IsZero():
			reply := replyTimesFrom(capPath, labKeyDefault, req.Add(-time.Second), req.Add(30*time.Second), true)
			wide("2. A restarted; the first re-authorization request", fmt.Sprintf("%s after the login, %s after the restart: %s",
				req.Sub(loginAt).Round(time.Second), req.Sub(restartAt).Round(time.Second), strings.Join(reply, "; ")))
		case !ended.IsZero():
			wide("2. A restarted; the session", fmt.Sprintf("ended %s after the login with no re-authorization request",
				ended.Sub(loginAt).Round(time.Second)))
			fail("the session ended before a re-authorization request")
		default:
			wide("2. A restarted; the first re-authorization request", "INVALID: none within 20 minutes of the restart")
			fail("no re-authorization request within 20 minutes of the restart (the session was open %s)",
				time.Since(loginAt).Round(time.Second))
		}
		recs := l.waitForRecords(offA, 30*time.Second, func(rs []map[string]any) bool { return len(reasonsOf(rs, "authorize_session")) > 0 })
		wide("2. port49d A's records since the restart", fmt.Sprintf("authorize_session %v; accounting %v", reasonsOf(recs, "authorize_session"),
			reasonsOf(recs, "accounting")))
		wide("2. the session after the re-authorization, `show version`", shellCell(l, sh, "show version"))

		// Revoke the principal and wait for the next re-authorization.
		revText, revOK := revokeCLI(s.AdminBroker, "--principal", slicePrincipal)
		if !revOK {
			fail("port49 revoke --principal: %s", revText)
		}
		revokeAt := time.Now()
		offA = l.mark()
		wide("3. `port49 revoke --principal` on the broker's socket", firstLine(revText))
		req2, ended2 := awaitReauthorization(t, l, sh, capPath, revokeAt, 20*time.Minute)
		switch {
		case !req2.IsZero():
			reply := replyTimesFrom(capPath, labKeyDefault, req2.Add(-time.Second), req2.Add(30*time.Second), true)
			wide("3. the next re-authorization request", fmt.Sprintf("%s after the revocation: %s",
				req2.Sub(revokeAt).Round(time.Second), strings.Join(reply, "; ")))
		case !ended2.IsZero():
			wide("3. the session", fmt.Sprintf("ended %s after the revocation with no further re-authorization request",
				ended2.Sub(revokeAt).Round(time.Second)))
		default:
			wide("3. the next re-authorization request", "INVALID: none within 20 minutes of the revocation")
			fail("no re-authorization request within 20 minutes of the revocation")
		}
		recs = l.waitForRecords(offA, 30*time.Second, func(rs []map[string]any) bool { return len(reasonsOf(rs, "authorize_session")) > 0 })
		wide("3. port49d A's records since the revocation", fmt.Sprintf("authorize_session %v", reasonsOf(recs, "authorize_session")))
		wide("3. the session after the denial, `show version`", shellCell(l, sh, "show version"))
		wide("3. whether the device ended the session", fmt.Sprintf("session ended: %v", sh.ended()))

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
