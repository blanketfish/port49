//go:build lab

package lab

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/tests/lab/labcreds"
)

const l29MidnightClaim = "What a device does when port49d resets an open connection at its first packet past the " +
	"connection's key version's retire_after, across a real 00:00:00Z: the command in flight, and the next " +
	"connections, compared with L28's expired phase (spec §15 L29)."

// untilUTC sleeps until at, writing a line a minute so the stall watchdog
// sees a live log.
func untilUTC(t *testing.T, at time.Time) {
	t.Helper()
	for time.Now().Before(at) {
		left := time.Until(at)
		t.Logf("l29: waiting for %s, %s left", at.Format("15:04:05Z"), left.Round(time.Second))
		time.Sleep(min(left, time.Minute))
	}
}

// TestL29Midnight holds a token session open across a real 00:00:00Z with the
// device's key version retiring at it. retire_after is a date (spec §10), so
// the instant cannot be moved to a daytime one without faking port49d's
// clock, which would stop measuring the path production takes.
//
// Single-connection is set as soon as the device is up: it is device
// configuration, which holds until midnight, and its admin CLI restarts
// port49d on the standing config. At 23:50Z the device's clock is read, and
// the daemon is restarted on the midnight config and probed until the device
// is asking it, so the minutes before midnight hold nothing but the session.
//
// The same command, `show version` (permitted by the lab policy, and what
// L28's phases time), runs before and after midnight, so the only thing that
// changes across 00:00:00Z is the date. The premise is asserted, not only
// recorded: a night where port49d did not admit the session under v1 before
// midnight, or retired it early, or admitted v1 after, fails rather than
// writing a note that reads as L29's answer.
func TestL29Midnight(t *testing.T) {
	if os.Getenv("PORT49_L29_MIDNIGHT") != "1" {
		t.Skip("L29's midnight case runs only across a real 00:00:00Z: set PORT49_L29_MIDNIGHT=1 and start the " +
			"run in the evening (plan 6b Task 20)")
	}
	eachPlatform(t, func(t *testing.T, l *lab) {
		now := time.Now().UTC()
		midnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
		if time.Until(midnight) < 15*time.Minute {
			t.Fatal("the device came up too late for tonight's midnight; start the run earlier")
		}
		single := l.singleConnection(t)
		t.Logf("l29: single-connection: %s", single)
		untilUTC(t, midnight.Add(-10*time.Minute))
		clock := l.deviceClock(t)
		t.Logf("l29: %s", clock)
		if os.Getenv("PORT49_L28_NEW_KEY") == "" {
			t.Setenv("PORT49_L28_NEW_KEY", labcreds.RotationKey)
		}
		// v1, the device's key, admits through the end of today UTC and not after
		// (spec §10, "retire_after is a date, inclusive").
		today := midnight.Add(-time.Hour).Format("2006-01-02")
		live := l.l28Live(t, l.l28Config(t, "midnight", "  lab_key:\n    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}\n"+
			"    accept: [{version: 1, secret_env: PORT49_LAB_KEY, retire_after: "+today+"}]\n"))
		if t.Failed() {
			t.Fatalf("the device was not asking port49d on the midnight config (%s); this night missed its midnight", live)
		}
		if time.Until(midnight) < 3*time.Minute {
			t.Fatal("port49d on the midnight config was not reached before 23:57Z; this night missed its midnight")
		}
		stop := l.capture(t, "L29-midnight")
		defer stop()
		untilUTC(t, midnight.Add(-3*time.Minute))
		off := l.mark()
		user, secret := l.nextLogin(t)
		sh, err := l.shell(user, secret)
		if err != nil {
			t.Fatalf("the token session before midnight: %v", err)
		}
		defer sh.Close()
		var before []string
		for _, at := range []time.Duration{-2 * time.Minute, -time.Minute} {
			untilUTC(t, midnight.Add(at))
			out, took, err := sh.Run("show version", 30*time.Second)
			if err != nil {
				t.Fatalf("show version at %s: %v", midnight.Add(at).Format("15:04Z"), err)
			}
			if l29Refused(out) {
				t.Fatalf("show version at %s, before midnight, was refused: %q; this night measures nothing",
					midnight.Add(at).Format("15:04Z"), firstLine(out))
			}
			before = append(before, took.Round(10*time.Millisecond).String())
		}
		untilUTC(t, midnight.Add(5*time.Second))
		out, took, err := sh.Run("show version", 60*time.Second)
		inFlight := fmt.Sprintf("printed its output in %s", took.Round(10*time.Millisecond))
		if err != nil {
			t.Errorf("show version past midnight not observed in 60s: %v", err)
			inFlight = "not observed in 60s"
		} else if l29Refused(out) {
			inFlight = fmt.Sprintf("refused in %s: %q", took.Round(10*time.Millisecond), firstLine(out))
		}
		recs := l.drainRecords(off, 10*time.Second)
		lastV1, reset := l29Premise(t, recs, user, midnight)
		untilUTC(t, midnight.Add(30*time.Second))
		offNext := l.mark()
		next := l.timedLogins(t)
		nextRecs := l.drainRecords(offNext, 10*time.Second)
		diags, versions := l29Counts(nextRecs)
		capLine := l.captureLine(t)
		stop()
		l.result(t, "L29-midnight", l29MidnightClaim, fmt.Sprintf("retire_after: %s (v1 admits through "+
			"%sT23:59:59.999Z). %s %s Last record under v1: %s. First packet refused as retired: %s; the record "+
			"cannot say whether that packet was on the connection open across midnight or the first packet of a "+
			"new one (an unvalidated record carries the source address, not its port), so which it was is read "+
			"from the capture. Single-connection: %s.\n\n| step | outcome |\n|---|---|\n"+
			"| `show version` at 23:58Z and 23:59Z | ran in %s |\n| `show version` at 00:00:05Z, same session | %s |\n"+
			"%s\nRecords from the token login at 23:57Z to the command after midnight:\n\n```%s\n```\n\n"+
			"Records from the logins after midnight: unvalidated by diagnosis/type %v; validated by key version %v."+
			"\n\nWhether one connection spanned 00:00:00Z is read from the capture's 4-tuples: %s\n\n"+
			"Compare `tests/lab/results/L28-%s.md`'s `expired` and `stopped` phases.\n",
			today, today, clock, live, lastV1, reset, single, strings.Join(before, ", "), inFlight, next,
			summarize(recs), diags, versions, capLine, l.p.name))
	})
}

// l29Refused reports whether a command's output is the device refusing it.
func l29Refused(out string) bool {
	return strings.Contains(out, "% ") || strings.Contains(out, "error:") ||
		strings.Contains(strings.ToLower(out), "authorization failed")
}

// l29Premise checks that the records hold what the night is premised on, and
// returns the last v1 record's time and the first matches_retired record's:
// the token session admitted under v1 in [23:58Z, 00:00:00Z), no v1 record at
// or after 00:00:00Z, and no packet refused as retired before it.
func l29Premise(t *testing.T, recs []map[string]any, user string, midnight time.Time) (lastV1, reset string) {
	t.Helper()
	lastV1, reset = "none", "none"
	sessionV1 := false
	for _, r := range recs {
		ts, ok := recTime(r)
		if !ok {
			continue
		}
		if d := sub(r, "device"); d != nil && d["key_version"] == float64(1) {
			lastV1 = ts.UTC().Format(time.RFC3339Nano)
			if !ts.Before(midnight) {
				t.Errorf("a record under v1 at %s, at or after 00:00:00Z: v1 was not retired at midnight", lastV1)
			}
			if s := sub(r, "session"); s != nil && str(s, "username") == user &&
				!ts.Before(midnight.Add(-2*time.Minute)) && ts.Before(midnight) {
				sessionV1 = true
			}
		}
		if u := sub(r, "unvalidated"); u != nil && reset == "none" && str(u, "diagnosis") == "matches_retired" {
			reset = ts.UTC().Format(time.RFC3339Nano)
			if ts.Before(midnight) {
				t.Errorf("a packet refused as retired at %s, before 00:00:00Z", reset)
			}
		}
	}
	if !sessionV1 {
		t.Errorf("no record for %s under v1 in [23:58Z, 00:00:00Z): the session was not shown to be admitted "+
			"under v1 before midnight", user)
	}
	return lastV1, reset
}

// l29Counts is l28Phase's tally: unvalidated records by diagnosis/type, and
// validated records by key version.
func l29Counts(recs []map[string]any) (diags, versions map[string]int) {
	diags, versions = map[string]int{}, map[string]int{}
	for _, r := range recs {
		if u := sub(r, "unvalidated"); u != nil {
			typ, _ := u["type"].(float64)
			diags[str(u, "diagnosis")+"/"+l28Types[int(typ)]]++
		}
		if d := sub(r, "device"); d != nil {
			if v, ok := d["key_version"].(float64); ok {
				versions[fmt.Sprintf("v%d", int(v))]++
			}
		}
	}
	return diags, versions
}

// deviceClock reads the device's clock over the break-glass admin CLI, with
// port49d stopped so the command is authorized locally, bracketed by the
// host's clock. The host clock is the reference: port49d reads it, and every
// time in the note is the host's. vJunos-router 23.4R2-S2.1 answers `show
// clock` with `syntax error, expecting <command>.` (checked by a daytime
// smoke run on 2026-09-30), so on Junos the clock is `show system uptime`'s
// `Current time:` line.
func (l *lab) deviceClock(t *testing.T) string {
	t.Helper()
	cmd, open := "show clock", adminCLI
	if strings.HasPrefix(l.p.name, "juniper_") {
		cmd = "show system uptime"
		open = func(l *lab) (*cliConn, error) { return l.junosCLI(breakglassUser, breakglassPassword) }
	}
	var out string
	var h0, h1 time.Time
	l.withAdminCLI(t, open, func(c *cliConn) error {
		var err error
		h0 = time.Now().UTC()
		if strings.HasPrefix(l.p.name, "juniper_") {
			out, err = junosShow(c, cmd)
		} else {
			out, err = l.adminShow(c, cmd)
		}
		h1 = time.Now().UTC()
		if err != nil {
			return fmt.Errorf("the device clock (%s): %w", cmd, err)
		}
		return nil
	})
	said := l29Output(out, l.p.node)
	if strings.HasPrefix(l.p.name, "juniper_") {
		said, _, _ = strings.Cut(said, "; ")
	}
	return fmt.Sprintf("Device clock, `%s` over break-glass with port49d stopped: `%s`; host clock %s before, "+
		"%s after. The host clock is the reference: port49d reads it, and every time here is the host's.",
		cmd, said, h0.Format("15:04:05.000Z"), h1.Format("15:04:05.000Z"))
}

// l29Output is a command's reply without its echo, blank lines or the prompt
// after it, one line per `; `.
func l29Output(out, node string) string {
	lines := strings.Split(strings.ReplaceAll(out, "\r", ""), "\n")
	if len(lines) > 0 {
		lines = lines[1:]
	}
	var kept []string
	for _, ln := range lines {
		if ln = strings.TrimSpace(ln); ln != "" && !strings.Contains(ln, node) {
			kept = append(kept, ln)
		}
	}
	return strings.Join(kept, "; ")
}
