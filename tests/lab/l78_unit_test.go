package lab

import (
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
		ran, record bool
		total       int
		shown       string
		lockout     bool
		says        string
	}{
		{true, true, 375, "Hostname: srx1", false, "logged in and ran"},
		{false, true, 375, "", true, "refused after a permit reply of 375 bytes"},
		{false, false, 0, "", false, "not observed"},
		{true, false, 0, "Hostname: srx1", false, "no authorize_session record"},
		// The 400 and 600 rows: the login worked and the device refused the command.
		{true, true, 124, "error: unknown command: show", false, "`show version` refused (deny-all)"},
	}
	for _, c := range cases {
		lockout, says := l78Grade(c.ran, c.record, c.total, c.shown)
		if lockout != c.lockout || !strings.Contains(says, c.says) {
			t.Errorf("ran=%v record=%v: got %v %q, want %v containing %q", c.ran, c.record, lockout, says, c.lockout, c.says)
		}
	}
}

func TestL78ConclusionNamesTheLargestLoginAndKeepsTheRowOpen(t *testing.T) {
	rows := []l78Row{{Target: 200, Total: 208, LoggedIn: true}, {Target: 375, Total: 375, LoggedIn: true}, {Target: 400, Total: 124, LoggedIn: true}}
	got := l78Conclusion(rows, "vJunos-router 23.4R2-S2.1")
	want := "no lockout up to 375 bytes on vJunos-router 23.4R2-S2.1; open for hardware Junos"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	rows = append(rows, l78Row{Target: 600, Total: 380, Lockout: true})
	if got := l78Conclusion(rows, "x"); !strings.Contains(got, "lockout at 380 bytes") {
		t.Fatalf("a lockout was not named: %q", got)
	}
}
