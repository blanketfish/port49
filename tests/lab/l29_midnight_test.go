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
// port49d on the standing config. The daemon is restarted on the midnight
// config at 23:50Z and probed until the device is asking it, so the minutes
// before midnight hold nothing but the session.
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
		untilUTC(t, midnight.Add(-10*time.Minute))
		if os.Getenv("PORT49_L28_NEW_KEY") == "" {
			t.Setenv("PORT49_L28_NEW_KEY", labcreds.RotationKey)
		}
		// v1, the device's key, admits through the end of today UTC and not after
		// (spec §10, "retire_after is a date, inclusive").
		today := midnight.Add(-time.Hour).Format("2006-01-02")
		live := l.l28Live(t, l.l28Config(t, "midnight", "  lab_key:\n    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}\n"+
			"    accept: [{version: 1, secret_env: PORT49_LAB_KEY, retire_after: "+today+"}]\n"))
		if time.Until(midnight) < 3*time.Minute {
			t.Fatal("port49d on the midnight config was not reached before 23:57Z; this night missed its midnight")
		}
		stop := l.capture(t, "L29-midnight")
		defer stop()
		untilUTC(t, midnight.Add(-3*time.Minute))
		user, secret := l.nextLogin(t)
		sh, err := l.shell(user, secret)
		if err != nil {
			t.Fatalf("the token session before midnight: %v", err)
		}
		defer sh.Close()
		off := l.mark()
		var before []string
		for _, at := range []time.Duration{-2 * time.Minute, -time.Minute} {
			untilUTC(t, midnight.Add(at))
			if _, took, err := sh.Run("show version", 30*time.Second); err != nil {
				t.Fatalf("show version at %s: %v", midnight.Add(at).Format("15:04Z"), err)
			} else {
				before = append(before, took.Round(10*time.Millisecond).String())
			}
		}
		// Junos has no `show clock`; `show system uptime` prints its current time.
		clock := "show clock"
		if strings.HasPrefix(l.p.name, "juniper_") {
			clock = "show system uptime"
		}
		untilUTC(t, midnight.Add(5*time.Second))
		out, took, err := sh.Run(clock, 60*time.Second)
		inFlight := fmt.Sprintf("printed its output in %s", took.Round(10*time.Millisecond))
		if err != nil {
			t.Errorf("%s past midnight not observed in 60s: %v", clock, err)
			inFlight = "not observed in 60s"
		} else if strings.Contains(out, "% ") || strings.Contains(out, "error:") ||
			strings.Contains(strings.ToLower(out), "authorization failed") {
			inFlight = fmt.Sprintf("refused in %s: %q", took.Round(10*time.Millisecond), firstLine(out))
		}
		recs := l.drainRecords(off, 10*time.Second)
		// The instants the run actually held: the last record v1 admitted,
		// and the first packet refused as retired.
		lastV1, reset := "none", "none"
		for _, r := range recs {
			ts, _ := recTime(r)
			if d := sub(r, "device"); d != nil && d["key_version"] == float64(1) {
				lastV1 = ts.UTC().Format(time.RFC3339Nano)
			}
			if u := sub(r, "unvalidated"); u != nil && reset == "none" && str(u, "diagnosis") == "matches_retired" {
				reset = ts.UTC().Format(time.RFC3339Nano)
			}
		}
		untilUTC(t, midnight.Add(30*time.Second))
		next := l.timedLogins(t)
		capLine := l.captureLine(t)
		stop()
		l.result(t, "L29-midnight", l29MidnightClaim, fmt.Sprintf("retire_after: %s (v1 admits through "+
			"%sT23:59:59.999Z). %s Last record under v1: %s; first packet refused as retired: %s. "+
			"Single-connection: %s.\n\n| step | outcome |\n|---|---|\n"+
			"| `show version` at 23:58Z and 23:59Z | ran in %s |\n| `%s` at 00:00:05Z, same session | %s |\n"+
			"| records from 23:57Z | %s |\n%s\nWhether one connection spanned 00:00:00Z is read from the capture's "+
			"4-tuples: %s\n\nCompare `tests/lab/results/L28-%s.md`'s `expired` and `stopped` phases.\n",
			today, today, live, lastV1, reset, single, strings.Join(before, ", "), clock, inFlight, summarize(recs), next,
			capLine, l.p.name))
	})
}
