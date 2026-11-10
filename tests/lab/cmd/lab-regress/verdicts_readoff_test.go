package main

import (
	"strings"
	"testing"
)

const readOffNote = "## Observation\n\n### Read off the table\n\n" +
	"- explicit anchors with the pipe tail: true: `^show( *\\|.*)?$` refused `show version` (true) and ran `show x` (true)\n" +
	"- JunosFacts.CaseSensitive = false: false only where every spelling was refused\n" +
	"- narrow shape exact: true: ran `show version` true; refused `ping` true\n" +
	"- **Ruling 15 may close on this run:** true (the control held: true)\n" +
	"- a bullet with no verdict word at all\n"

func TestReadOffBulletsAreVerdictRows(t *testing.T) {
	rows := verdictRows(readOffNote)
	if len(rows) != 5 {
		t.Fatalf("want 5 rows (4 claims and a bare bullet), got %d: %v", len(rows), rows)
	}
	flips := []struct{ from, to string }{
		{"pipe tail: true:", "pipe tail: false:"},
		{"CaseSensitive = false:", "CaseSensitive = true:"},
		{"refused `ping` true", "refused `ping` false"},
		{"**Ruling 15 may close on this run:** true", "**Ruling 15 may close on this run:** false"},
	}
	for _, f := range flips {
		got := verdictChanges(readOffNote, strings.Replace(readOffNote, f.from, f.to, 1))
		if len(got) != 1 {
			t.Errorf("flipping %q: want one change, got %v", f.from, got)
		}
	}
}

func TestReadOffProseIsNotAVerdict(t *testing.T) {
	now := strings.Replace(readOffNote, "false only where every spelling was refused", "false, as measured on this image", 1)
	now = strings.Replace(now, "(the control held: true)", "(the control held: true, again)", 1)
	if got := verdictChanges(readOffNote, now); len(got) != 0 {
		t.Fatalf("reworded prose around the same verdict words is not a change: %v", got)
	}
}
