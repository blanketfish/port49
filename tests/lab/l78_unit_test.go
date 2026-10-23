package lab

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// This checks l78's arithmetic only: l78Bytes is built from the numbers the
// projection rendered when the steps were chosen (`port49 explain`), so it
// cannot catch the projection rendering differently. The measured total is the
// authorize_session record's reply.attributes, which TestL78 records and the
// note cites.
func TestL78StepsRenderTheirTotalWithEveryAttributeUnder255(t *testing.T) {
	for _, s := range l78Steps {
		perm, deny, allow := l78Bytes(s.Deny, s.Allow)
		if !s.FailClosed {
			if perm > 255 || deny > 255 || allow > 255 {
				t.Errorf("%d: an attribute over 255 (user-permissions %d, deny-commands %d, allow-commands %d)", s.Target, perm, deny, allow)
			}
			if got := perm + deny + allow; got != s.Want {
				t.Errorf("%d: renders %d, the step says %d", s.Target, got, s.Want)
			}
			continue
		}
		// A step the projection cannot carry: the deny-commands value passes 255,
		// so the projection fails closed (decision 26).
		if deny <= 255 {
			t.Errorf("%d: a fail-closed step whose deny-commands is %d bytes", s.Target, deny)
		}
	}
}

func TestL78StepsAreOrderedAndReachTheBriefsTotals(t *testing.T) {
	var targets []int
	last := 0
	for _, s := range l78Steps {
		targets = append(targets, s.Target)
		if !s.FailClosed && s.Want < last {
			t.Errorf("%d renders %d, below the step before it (%d)", s.Target, s.Want, last)
		}
		if !s.FailClosed {
			last = s.Want
		}
	}
	for _, want := range []int{200, 240, 256, 300, 400, 600} {
		found := false
		for _, got := range targets {
			found = found || got == want
		}
		if !found {
			t.Errorf("the brief's total %d is not a step (steps: %v)", want, targets)
		}
	}
}

func TestL78PolicyNamesItsPermitsAndDenies(t *testing.T) {
	for _, s := range l78Steps {
		pol := l78Policy(s)
		for _, root := range l78Roots[:s.Allow] {
			if !strings.Contains(pol, `"`+root+` **"`) {
				t.Errorf("%d: no permit of %s", s.Target, root)
			}
		}
		for _, d := range l78Denies[:s.Deny] {
			if !strings.Contains(pol, `"`+d+`"`) {
				t.Errorf("%d: no deny of %s", s.Target, d)
			}
		}
		if !strings.Contains(pol, "max_privilege: admin") || !strings.Contains(pol, "username: qual01") {
			t.Errorf("%d: the policy is not the qual subject's", s.Target)
		}
	}
}

func TestL78ReplyBytesSumsTheAttributesOfAPermit(t *testing.T) {
	rec := map[string]any{"event": "authorize_session", "verdict": "permit",
		"reply": map[string]any{"attributes": []any{"user-permissions=a", "deny-commands=bb"}}}
	parts, total, ok := l78Reply(rec)
	if !ok || total != 34 || len(parts) != 2 || parts[0] != 18 || parts[1] != 16 {
		t.Fatalf("got %v, %d, %v", parts, total, ok)
	}
	rec["verdict"] = "deny"
	if _, _, ok := l78Reply(rec); ok {
		t.Fatal("a deny's reply counted as a permit reply")
	}
	if _, _, ok := l78Reply(map[string]any{"event": "authorize_session", "verdict": "permit"}); ok {
		t.Fatal("a record with no reply counted")
	}
}

func TestL78GradeNeedsAPermitRecordBeforeItNamesALockout(t *testing.T) {
	cases := []struct {
		loggedIn, record, failClosed bool
		total                        int
		out                          string
		lockout, counts, ok          bool
		says, shown                  string
	}{
		{true, true, false, 375, "Hostname: srx1\nModel: vmx", false, true, true, "logged in and ran", "Hostname: srx1"},
		{false, true, false, 375, "", true, false, true, "refused after a permit reply of 375 bytes", ""},
		{false, false, false, 0, "", false, false, true, "not observed", ""},
		{true, false, false, 0, "Hostname: srx1", false, false, true, "no authorize_session record", "Hostname: srx1"},
		// The 400 and 600 rows: the login worked and the device refused the command.
		{true, true, true, 124, "error: unknown command: show", false, false, true, "`show version` refused (deny-all)", "error: unknown command: show"},
		// Final review I4 (a): a permit reply whose command the device refused is a
		// partial failure, not a pass, and never counts toward "no lockout up to".
		{true, true, false, 299, "error: permission denied", false, false, false, "refused `show version` under a permit reply of 299 bytes", "error: permission denied"},
		// I4 (b): Junos's caret line is no answer; the refusal under it is.
		{true, true, false, 299, "\n          ^\nunknown command.", false, false, false, "refused `show version` under a permit reply of 299 bytes", "unknown command."},
		{true, true, true, 124, "          ^\nunknown command.", false, false, true, "`show version` refused (deny-all)", "unknown command."},
		// A fail-closed reply under which the command ran: deny-all did not hold.
		{true, true, true, 124, "Hostname: srx1", false, false, false, "ran `show version` under the fail-closed reply of 124 bytes", "Hostname: srx1"},
		// Logged in under a permit reply and answered nothing: the command did not run.
		// M9: no output at all measures nothing, so the grade claims neither a run nor a refusal.
		{true, true, false, 208, "", false, false, false, "whether `show version` ran is unmeasured", ""},
		{true, true, true, 124, "", false, false, false, "whether `show version` ran is unmeasured", ""},
		{true, true, true, 124, "\r\n", false, false, false, "whether `show version` ran is unmeasured", ""},
		// Logged in with no record: the reply is unknown, so no output keeps its grade.
		{true, false, true, 0, "", false, false, true, "no authorize_session record showed the reply", ""},
	}
	for _, c := range cases {
		g := l78Grade(c.loggedIn, c.record, c.failClosed, c.total, c.out)
		if g.Lockout != c.lockout || g.Counts != c.counts || g.OK != c.ok || !strings.Contains(g.Says, c.says) || g.Shown != c.shown {
			t.Errorf("%+v: got %+v", c, g)
		}
	}
}

func TestL78ConclusionNamesTheLargestLoginAndKeepsTheRowOpen(t *testing.T) {
	rows := []l78Row{{Target: 200, Total: 208, LoggedIn: true, Counts: true}, {Target: 375, Total: 375, LoggedIn: true, Counts: true},
		{Target: 400, Total: 124, LoggedIn: true}}
	got := l78Conclusion(rows, "vJunos-router 23.4R2-S2.1")
	want := "no lockout up to 375 bytes on vJunos-router 23.4R2-S2.1; open for hardware Junos"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// A refused show version under a bigger permit reply is not "no lockout" there (final review I4).
	refused := append(rows, l78Row{Target: 450, Total: 450, LoggedIn: true})
	if got := l78Conclusion(refused, "vJunos-router 23.4R2-S2.1"); got != want {
		t.Fatalf("a refused step counted: %q", got)
	}
	rows = append(rows, l78Row{Target: 600, Total: 380, Lockout: true})
	if got := l78Conclusion(rows, "x"); !strings.Contains(got, "lockout at 380 bytes") {
		t.Fatalf("a lockout was not named: %q", got)
	}
}

// The committed vJunos rows read the same under the new grader (final review I4):
// each row's login column and the note's result are rebuilt from the row's
// target, reply bytes and the device's first line, and must match byte for byte.
func TestL78CommittedRowsGradeTheSame(t *testing.T) {
	notes, _ := filepath.Glob("results/L78-*.md")
	if len(notes) != 2 {
		t.Fatalf("want the two vJunos L78 notes, found %v", notes)
	}
	rowRx := regexp.MustCompile("^\\| (\\d+) \\| (\\d+) \\([^)]*\\) \\| (.*); the device's first line: `([^`]*)` \\| ")
	resultRx := regexp.MustCompile(`\*\*Result: (.*) on (.*); open for hardware Junos\.\*\*`)
	for _, n := range notes {
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		var rows []l78Row
		for _, ln := range strings.Split(string(b), "\n") {
			m := rowRx.FindStringSubmatch(ln)
			if m == nil {
				continue
			}
			target, _ := strconv.Atoi(m[1])
			total, _ := strconv.Atoi(m[2])
			failClosed := false
			for _, s := range l78Steps {
				if s.Target == target {
					failClosed = s.FailClosed
				}
			}
			g := l78Grade(true, true, failClosed, total, m[4])
			if !g.OK || g.Says != m[3] || g.Shown != m[4] {
				t.Errorf("%s step %d: committed %q (%q), graded now %+v", n, target, m[3], m[4], g)
			}
			rows = append(rows, l78Row{Target: target, Total: total, LoggedIn: true, Counts: g.Counts, Lockout: g.Lockout})
		}
		if len(rows) != len(l78Steps) {
			t.Fatalf("%s: %d rows parsed, want %d", n, len(rows), len(l78Steps))
		}
		m := resultRx.FindStringSubmatch(string(b))
		if m == nil {
			t.Fatalf("%s: no result line", n)
		}
		if got := l78Conclusion(rows, m[2]); got != m[1]+" on "+m[2]+"; open for hardware Junos" {
			t.Errorf("%s: committed %q, concluded now %q", n, m[1], got)
		}
	}
}
