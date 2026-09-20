//go:build lab

package lab

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// L13: how long a device waits for a TACACS+ reply, and what it does when
// port49's FAIL arrives after that.
//
// This is not an idle question about device tuning. port49 delays a FAIL reply
// on purpose, by `limits.auth_failure_delay_base` doubling per failure up to
// `limits.auth_failure_delay_max` (default 500ms and **5s**, internal/config).
// The delay holds the connection's read goroutine for its duration, and
// nobody had measured what any device does while it is held. If the ceiling
// sits above a device's reply timeout, the device stops waiting and the FAIL
// port49 believes it sent is a reply nothing received — and a device that then
// treats the server as *unreachable* rather than as having denied is exactly
// the fall-through case §5.6 rests on (L4).
//
// Method: set base and max to the same value, so the very first failure for a
// (nas, username) pair carries the full delay and no failures have to be driven
// first. Then log in as a local account port49 has no token for, so the reply
// is a FAIL, and time the login from the client side. The elapsed time says
// whether the device waited for the reply or gave up before it came.
var l13Delays = []time.Duration{2 * time.Second, 6 * time.Second, 12 * time.Second}

type l13Row struct {
	delay    time.Duration
	took     time.Duration
	ok       bool
	err      error
	attempts int    // redeem records for this account in the window
	reasons  string // their reason codes
}

func TestL13ReplyTimeout(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		stop := l.capture(t, "L13")
		defer stop()

		// Read the device's own timers with port49d stopped. On EOS a local
		// account cannot log in at all while port49 is up and denying it (L4),
		// so a CLI opened in any other condition is a coin toss on the platform.
		if err := l.stopDaemon(); err != nil {
			t.Fatalf("could not stop port49d before reading the device's timers: %v", err)
		}
		configured := l13ConfiguredTimeout(t, l)

		var rows []l13Row
		for _, d := range l13Delays {
			if err := l.stopDaemon(); err != nil {
				t.Fatalf("could not stop port49d to change its failure delay: %v", err)
			}
			cfg := l.writeDelayConfig(t, d)
			if err := l.startDaemonWith(cfg, true); err != nil {
				t.Fatalf("could not start port49d with a %v failure delay: %v", d, err)
			}
			rows = append(rows, l.l13Attempt(t, d))
		}

		// Put the daemon back on the lab config, so nothing later in the run
		// inherits a 12-second failure delay.
		if err := l.stopDaemon(); err != nil {
			t.Errorf("could not stop the delayed daemon: %v", err)
		} else if cfg, err := l.configPath(); err != nil {
			t.Fatalf("derive this platform's daemon config: %v", err)
		} else if err := l.startDaemonWith(cfg, true); err != nil {
			t.Fatalf("could not restart port49d on the lab config: %v", err)
		}

		measured := 0
		for _, r := range rows {
			if r.attempts > 0 || r.took > 0 {
				measured++
			}
		}
		if measured == 0 {
			t.Fatal("no login attempt produced a timing or a decision record, so no reply timeout was measured")
		}
		l.result(t, "L13", l13Claim, l13Observation(l, configured, rows))
	})
}

// l13Attempt makes one login whose reply port49 will delay by d.
func (l *lab) l13Attempt(t *testing.T, d time.Duration) l13Row {
	t.Helper()
	r := l13Row{delay: d}
	off := l.mark()
	t0 := time.Now()
	c, err := l.dial(breakglassUser, breakglassPassword, 3*time.Minute)
	r.took = time.Since(t0)
	if err == nil {
		r.ok = true
		c.Close()
	} else {
		r.err = err
	}
	// Wait past the delay for the record: it is emitted after the sleep, so a
	// window shorter than the delay would read "no reply was sent" off a reply
	// that was merely still pending.
	recs := l.waitForRecords(off, d+30*time.Second, func(rs []map[string]any) bool {
		return redeemFor(rs, breakglassUser) != nil
	})
	var reasons []string
	for _, rec := range recs {
		if str(rec, "event") != "redeem" {
			continue
		}
		if s := sub(rec, "session"); s != nil && str(s, "username") == breakglassUser {
			r.attempts++
			reasons = append(reasons, fmt.Sprintf("%s/%s", str(rec, "verdict"), str(rec, "reason")))
		}
	}
	r.reasons = strings.Join(reasons, ", ")
	if r.reasons == "" {
		r.reasons = "—"
	}
	return r
}

// l13ConfiguredTimeout asks the device what its own TACACS+ reply timeout is,
// so the note quotes the device rather than a vendor web page.
func l13ConfiguredTimeout(t *testing.T, l *lab) string {
	t.Helper()
	if strings.HasPrefix(l.p.name, "juniper_") {
		c, err := l.junosCLI(breakglassUser, breakglassPassword)
		if err != nil {
			return "Not read: no CLI channel was available (" + err.Error() + ")."
		}
		defer c.Close()
		// `display inheritance defaults` is the one that answers the question: it
		// prints the value the device will use, including one the configuration
		// never states.
		// `display set` on the end drops the file's comments, which are long
		// enough to bury the statement they sit above.
		cfg, cfgErr := junosShow(c, "show configuration system tacplus-server | display inheritance defaults | display set | no-more")
		cfgOut := redactSecrets(strings.TrimSpace(stripPrompt(cfg)))
		if cfgErr != nil {
			cfgOut = "(the device did not answer: " + cfgErr.Error() + ")"
		}
		refOut := "(not available on this image)"
		if ref, err := junosShow(c, "help reference system tacplus-server | no-more"); err == nil {
			refOut = redactSecrets(strings.TrimSpace(l13GrepTimeout(stripPrompt(ref))))
		}
		return fmt.Sprintf("`show configuration system tacplus-server | display inheritance defaults`:\n\n"+
			"```\n%s\n```\n\nWhat the device's own reference says about `timeout` "+
			"(`help reference system tacplus-server`):\n\n```\n%s\n```",
			cfgOut, refOut)
	}
	if l.p.name == "cisco_nxos" {
		c, err := l.nxosCLI(breakglassUser, breakglassPassword)
		if err != nil {
			return "Not read: no CLI channel was available (" + err.Error() + ")."
		}
		defer c.Close()
		// `show tacacs-server` is the one that prints the timer. NX-OS states a
		// global timeout there whether or not the configuration sets one, which
		// makes it the only platform in this lab that names its own figure — so
		// the note can be read against the device's claim rather than only
		// against the measurement.
		show, _ := nxosShow(c, "show tacacs-server")
		groups, _ := nxosShow(c, "show tacacs-server groups")
		cfg, _ := nxosShow(c, "show running-config | include tacacs")
		return fmt.Sprintf("`show tacacs-server`:\n\n```\n%s\n```\n\n`show tacacs-server groups`:\n\n```\n%s\n```\n\n"+
			"`show running-config | include tacacs`:\n\n```\n%s\n```",
			redactSecrets(strings.TrimSpace(stripPrompt(show))),
			redactSecrets(strings.TrimSpace(stripPrompt(groups))),
			redactSecrets(strings.TrimSpace(stripPrompt(cfg))))
	}
	if l.p.name == "cisco_iosxe" {
		c, err := l.iosxeCLI(breakglassUser, breakglassPassword)
		if err != nil {
			return "Not read: no CLI channel was available (" + err.Error() + ")."
		}
		defer c.Close()
		// `show tacacs` prints the per-server state; `show aaa servers` carries
		// the per-request timeout counters, which say whether the device
		// believes it timed out at all.
		//
		// `show aaa servers` is NOT filtered through l13GrepTimeout the way the
		// Junos reference page is, and the 2026-09-20 run is why: filtered, it
		// produced an empty code block, and an empty block in a results note
		// reads as "the device said nothing" — the same class of false
		// statement the L2 flake made. Whatever the device says goes in whole,
		// and if it says nothing the note says so in words.
		show, showErr := iosxeShow(c, "show tacacs")
		servers, serversErr := iosxeShow(c, "show aaa servers")
		cfg, cfgErr := iosxeShow(c, "show running-config | include tacacs")
		return fmt.Sprintf("`show tacacs`:\n\n%s\n\n`show aaa servers`:\n\n%s\n\n"+
			"`show running-config | include tacacs`:\n\n%s",
			deviceSaid(show, showErr),
			deviceSaid(servers, serversErr),
			deviceSaid(cfg, cfgErr))
	}
	c, err := l.eosCLI(breakglassUser, breakglassPassword)
	if err != nil {
		return "Not read: no CLI channel was available (" + err.Error() + ")."
	}
	defer c.Close()
	show, _ := eosShow(c, "show tacacs")
	cfg, _ := eosShow(c, "show running-config | include tacacs")
	return fmt.Sprintf("`show tacacs`:\n\n```\n%s\n```\n\n`show running-config | include tacacs`:\n\n```\n%s\n```",
		redactSecrets(strings.TrimSpace(stripPrompt(show))), redactSecrets(strings.TrimSpace(stripPrompt(cfg))))
}

// deviceSaid renders one command's output for a results note, and refuses to
// render nothing as an empty code block. A fenced block with nothing in it says
// "the device answered with silence", which is a measurement; it is almost
// always "the harness never got the answer", which is not.
func deviceSaid(out string, err error) string {
	body := redactSecrets(strings.TrimSpace(stripPrompt(out)))
	if body != "" {
		return "```\n" + body + "\n```"
	}
	if err != nil {
		return "Not read: the device did not answer within the harness's window (" + err.Error() + ")."
	}
	return "Not read: the device returned no output for this command. That is a gap in the note, " +
		"not a device that stayed silent — nothing here distinguishes the two."
}

// l13GrepTimeout keeps the part of a long `help reference` page that mentions
// the timeout, so the note quotes the relevant lines rather than a screenful.
func l13GrepTimeout(ref string) string {
	lines := strings.Split(ref, "\n")
	var keep []string
	for i, ln := range lines {
		if !strings.Contains(strings.ToLower(ln), "timeout") {
			continue
		}
		lo, hi := max(0, i-2), min(len(lines), i+12)
		keep = append(keep, lines[lo:hi]...)
	}
	if len(keep) == 0 {
		return "(the device's reference page says nothing about `timeout`)"
	}
	return strings.Join(keep, "\n")
}

// l13Verdict turns the rows into the sentence the register row is asking for:
// where the device stopped waiting, and what it did instead.
//
// A row where the device acted on the FAIL — refused the login — is a row it
// waited for. A row where the login succeeded is a row where it gave up and
// took the local password instead. The largest waited-out delay bounds the
// timeout from below and the smallest given-up one from above, so two rows on
// opposite sides pin it to an interval without a binary search.
//
// The classification is the **outcome**, not the elapsed time, and NX-OS is why
// it had to change. On the N9Kv the 6s row took 8.01s and logged in: longer
// than its own delay, so the elapsed-time rule filed it under "waited out" —
// and then the same note said the device accepted the local password, which is
// what a device does when it has stopped waiting. The reason for the gap is in
// the row beside it: the 2s row shows **two** redeem records for one login, so
// the device retransmits, and an elapsed time then measures the retransmission
// schedule rather than the reply timeout. A login that succeeded did not act on
// the FAIL, whatever the clock says, and that is the thing this row is about.
//
// On vEOS and both Junos images the two rules agree row for row, so the notes
// already committed for those platforms are unchanged by this.
func l13Verdict(rows []l13Row) string {
	var waited, gaveUp []l13Row
	for _, r := range rows {
		if r.ok {
			gaveUp = append(gaveUp, r)
		} else {
			waited = append(waited, r)
		}
	}
	if len(gaveUp) == 0 {
		return fmt.Sprintf("**The device acted on the denial every time.** No delay up to %s made it stop waiting "+
			"and take the local password, so its reply timeout is above that and this run does not bound it from "+
			"above.", rows[len(rows)-1].delay)
	}
	var b strings.Builder
	first := gaveUp[0]
	b.WriteString(fmt.Sprintf("**Measured reply timeout: about %s.** ", first.took.Round(100*time.Millisecond)))
	if len(waited) > 0 {
		last := waited[len(waited)-1]
		b.WriteString(fmt.Sprintf("A FAIL delayed by %s was acted on — the login was refused, %s elapsed. One "+
			"delayed by %s was not: that login **succeeded on the local password** after %s. So the timeout "+
			"lies between %s and %s.\n\n",
			last.delay, last.took.Round(10*time.Millisecond), first.delay, first.took.Round(10*time.Millisecond),
			last.delay, first.took.Round(100*time.Millisecond)))
	} else {
		b.WriteString(fmt.Sprintf("Even the shortest delay tried, %s, was not acted on: that login succeeded on "+
			"the local password.\n\n", first.delay))
	}
	b.WriteString("When the FAIL arrived after that, the device **accepted the local password**, exactly as it " +
		"does when the server is unreachable (L4). A denial delayed past the timeout is therefore not a denial: " +
		"it is indistinguishable from an outage, and the device takes the fall-through branch. ")
	retrans := 0
	for _, r := range rows {
		if r.attempts > 1 {
			retrans++
		}
	}
	if retrans > 0 {
		fmt.Fprintf(&b, "\n\n**This device retransmits**: %d of %d rows produced more than one redeem record for "+
			"a single login attempt. So the elapsed column measures the retransmission schedule as much as the "+
			"reply timeout, and the figure above is read off which logins the device acted on rather than off "+
			"the clock. ", retrans, len(rows))
	}
	b.WriteString("**port49's own default `limits.auth_failure_delay_max` is 5s** " +
		"(internal/config), reached after five consecutive failures for one `(nas, username)` pair. " +
		"Compare that with the figure above before treating a repeated-failure delay as a way to slow an " +
		"attacker down: past the device's timeout it stops slowing anything down and starts changing the " +
		"answer the device acts on.")
	return b.String()
}

const l13Claim = "Each device's TACACS+ reply timeout, and what the device does when a FAIL reply arrives after " +
	"it — reports an authentication failure, or treats the server as unreachable and falls through to the next " +
	"method or the next server."

func l13Observation(l *lab, configured string, rows []l13Row) string {
	var b strings.Builder
	fmt.Fprintf(&b, "### The device's own timeout\n\n%s\n\n### Late FAIL replies\n\n"+
		"port49d was restarted before each row with `limits.auth_failure_delay_base` and "+
		"`limits.auth_failure_delay_max` both set to the delay in the first column, so the **first** failure "+
		"for this account already carried the full delay and no failures had to be driven first. The login is "+
		"the local account `%s` presenting its own local password; port49 holds no token for it, so the reply "+
		"is FAIL (`token_not_found`), sent that long after the request arrived.\n\n",
		configured, breakglassUser)
	b.WriteString("| FAIL delayed by | SSH login | elapsed | redeem records for the account | reasons |\n|---|---|---|---|---|\n")
	for _, r := range rows {
		outcome := "refused"
		if r.ok {
			outcome = "**logged in**"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %s |\n", r.delay, outcome, r.took.Round(10*time.Millisecond), r.attempts, r.reasons)
	}
	fmt.Fprintf(&b, "\n%s\n\n", l13Verdict(rows))
	b.WriteString("\n**How to read the elapsed column.** An elapsed time at or just above the delay means the " +
		"device waited for the reply. An elapsed time well below it means the device stopped waiting, and what " +
		"it did next — refuse, or fall through to the local password — is the outcome column. More than one " +
		"redeem record for a single login attempt means the device gave up and asked again, which is the " +
		"retransmission half of the same behavior.\n\n")

	var errs []string
	for _, r := range rows {
		if r.err != nil {
			errs = append(errs, fmt.Sprintf("- %s delay: `%v`", r.delay, r.err))
		}
	}
	if len(errs) > 0 {
		b.WriteString("What SSH said when the login was refused:\n\n" + strings.Join(errs, "\n") + "\n\n")
	}

	fmt.Fprintf(&b, "### Not measured\n\n"+
		"- The method list in force is whatever `tests/lab/configs` deploys; this row does not sweep the "+
		"authentication order (that is L4).\n"+
		"- A second TACACS+ server, so \"tries the next server\" is untested — the lab has one.\n"+
		"- The device's retransmission and `deadtime` timers as configured values, beyond what the quoted "+
		"output above shows.\n"+
		"- Every transport but SSH, and every platform but %s.\n"+
		"- Delays above %s, and whether the connection is torn down by the device or by port49d.\n",
		l.p.version, l13Delays[len(l13Delays)-1])
	return b.String()
}
