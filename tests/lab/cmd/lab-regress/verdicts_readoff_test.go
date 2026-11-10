package main

import "testing"

// A bullet under a "Read off" heading is a row keyed by its subject; a bare bullet is a row too.
func TestReadOffBulletsAreRowsKeyedBySubject(t *testing.T) {
	note := "## Observation\n\n### Read off the table\n\n" +
		"- explicit anchors with the pipe tail: true: `^show( *\\|.*)?$` refused `show version` (true)\n" +
		"- JunosFacts.CaseSensitive = false: false only where every spelling was refused\n" +
		"- a bullet with no separator at all\n"
	rows := verdictRows(note)
	if len(rows) != 3 {
		t.Fatalf("want 3 rows, got %d: %v", len(rows), rows)
	}
	if rows[0].label != `explicit anchors with the pipe tail (under "Read off the table")` {
		t.Errorf("the subject is the text before the first colon: %q", rows[0].label)
	}
	if !flips(t, note, "CaseSensitive = false:", "CaseSensitive = true:") {
		t.Error("a flipped value must flag")
	}
}
