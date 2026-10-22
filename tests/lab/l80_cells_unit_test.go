package lab

import (
	"strings"
	"testing"
	"time"
)

// The cells are the design's: the baseline runs s1 and s3; the fixed arm adds
// sp, each idle gap at least 5 times (35 s twice), and three concurrent
// sessions of arm E's sequence 1 with `show users`.
func TestL80CellsAreTheDesigns(t *testing.T) {
	names := func(cs []l80Cell) string {
		var out []string
		for _, c := range cs {
			out = append(out, c.Name)
		}
		return strings.Join(out, ",")
	}
	if got := names(l80Cells("baseline")); got != "s1,s3" {
		t.Fatalf("baseline cells %s", got)
	}
	fixed := l80Cells("fixed")
	if got := names(fixed); got != "s1,s3,sp,idle29,idle30,idle31,idle35,concurrent" {
		t.Fatalf("fixed cells %s", got)
	}
	for _, c := range fixed {
		gaps := map[string]int{}
		for _, cmd := range c.Sessions[0] {
			if g, ok := strings.CutPrefix(cmd, "@sleep "); ok {
				gaps[g]++
			}
		}
		switch c.Name {
		case "idle29", "idle30", "idle31":
			if gaps[strings.TrimPrefix(c.Name, "idle")] < 5 {
				t.Errorf("%s samples its gap %v times, want at least 5", c.Name, gaps)
			}
		case "idle35":
			if gaps["35"] < 2 {
				t.Errorf("idle35 samples %v", gaps)
			}
		case "concurrent":
			if len(c.Sessions) != 3 || c.Sessions[0][len(c.Sessions[0])-1] != "show users" {
				t.Errorf("concurrent: %d sessions, %v", len(c.Sessions), c.Sessions[0])
			}
		}
		for _, s := range c.Sessions {
			for i, cmd := range s {
				if strings.HasPrefix(cmd, "@sleep ") && (i+1 >= len(s) || s[i+1] != "show users") {
					t.Errorf("%s: a gap not followed by `show users`", c.Name)
				}
			}
		}
	}
}

func TestL80AskMatchesRecordsInOrder(t *testing.T) {
	typed := []l80Typed{{Command: "terminal length 0"}, {Command: "show users"}, {Command: "terminal length 0"}, {Command: "show users"}}
	l80Ask(typed, []string{"show users", "terminal length 0", "show users"})
	if !typed[0].Asked || !typed[1].Asked || typed[2].Asked || !typed[3].Asked {
		t.Fatalf("%+v", typed)
	}
}

func TestL80StopsAreTheDesigns(t *testing.T) {
	ok := []l80Typed{{Command: "terminal length 0", Asked: true}, {Command: "show users", Asked: true, Denied: true}}
	if s := l80Stops("fixed", "idle31", ok, 1, 0); len(s) != 0 {
		t.Fatalf("a clean sample stops: %v", s)
	}
	lost := []l80Typed{{Command: "terminal length 0", Asked: true}, {Command: "show users", Gap: 31}}
	if s := l80Stops("fixed", "idle31", lost, 1, 0); len(s) != 2 {
		t.Fatalf("a lost and run `show users` is two stops: %v", s)
	}
	if s := l80Stops("baseline", "s1", lost, 1, 0); len(s) != 0 {
		t.Fatalf("the baseline stops on nothing: %v", s)
	}
	if s := l80Stops("fixed", "concurrent", ok, 2, 0); len(s) != 1 {
		t.Fatalf("two connections at once: %v", s)
	}
	if s := l80Stops("fixed", "concurrent", ok, 1, 1); len(s) != 1 {
		t.Fatalf("a second-connection count with every command asked: %v", s)
	}
	if s := l80Stops("fixed", "idle31", ok, 2, 1); len(s) != 0 {
		t.Fatalf("the connection stops are the concurrent cell's: %v", s)
	}
}

func TestL80MostOpen(t *testing.T) {
	at := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	c := func(syn, end time.Duration, how string) l73Conn {
		x := l73Conn{SYNAt: at.Add(syn), End: how}
		if how != "open" {
			x.EndAt = at.Add(end)
		}
		return x
	}
	if n := l80MostOpen([]l73Conn{c(0, time.Second, "server-fin"), c(2*time.Second, 3*time.Second, "server-fin")}); n != 1 {
		t.Fatalf("one after another: %d", n)
	}
	if n := l80MostOpen([]l73Conn{c(0, 0, "open"), c(2*time.Second, 3*time.Second, "server-fin")}); n != 2 {
		t.Fatalf("one held open: %d", n)
	}
}

// The timeline keeps the time, the event, the verdict and a command's words,
// and nothing else from a record.
func TestL80TimelineKeepsNoOtherField(t *testing.T) {
	recs := []map[string]any{
		{"ts": "2026-10-22T12:00:01.5Z", "event": "authorize_command", "verdict": "deny",
			"request": map[string]any{"vector": []any{"show", "users"}}, "credential_sha256": "fakehash01"},
		{"ts": "2026-10-22T12:00:02Z", "event": "unvalidated", "diagnosis": "fakediag"},
		{"ts": "2026-10-22T12:00:03Z", "event": "redeem", "verdict": "permit", "session": map[string]any{"username": "fakeuser9"}},
	}
	got := strings.Join(l80Timeline(recs), "\n")
	if got != "12:00:01.500 authorize_command deny \"show users\"\n12:00:03.000 redeem permit" {
		t.Fatalf("%q", got)
	}
}
