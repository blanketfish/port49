package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// jitterDurations changes every Go-style duration in a note ("1m12.9s", "320ms") to another one: the numbers a
// rerun moves.
var durationDigits = regexp.MustCompile(`\b(\d+)(\.\d+)?(ms|s|m|h)\b`)

// A table row's first cell is its key, and a duration there ("attempt 1 (hung 1s)") is a setting of the
// harness, not a measurement, so only the other cells move.
func jitterDurations(s string) string {
	lines := strings.Split(s, "\n")
	for i, ln := range lines {
		if strings.HasPrefix(ln, "|") {
			if j := strings.Index(ln[1:], "|"); j >= 0 {
				lines[i] = ln[:j+2] + durationDigits.ReplaceAllString(ln[j+2:], "7$3")
			}
			continue
		}
		lines[i] = durationDigits.ReplaceAllString(ln, "7$3")
	}
	return strings.Join(lines, "\n")
}

// TestEveryManifestNoteParsesItsVerdictsAndIgnoresDurations loads every note the manifest lists. A note whose
// entry does not say `verdicts: none` must parse at least one verdict row (a shape the parser misses must fail
// loudly, not pass silently), compare equal to itself, and compare equal to a copy whose durations moved.
func TestEveryManifestNoteParsesItsVerdictsAndIgnoresDurations(t *testing.T) {
	entries, err := loadManifest("../../regress.yaml", specPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		for _, n := range e.Notes {
			raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", n))
			if err != nil {
				t.Errorf("%s: %s: %v", e.ID, n, err)
				continue
			}
			note := string(raw)
			switch rows := len(verdictRows(note)); {
			case rows == 0 && !noVerdicts(e, n):
				t.Errorf("%s: %s parses 0 verdict rows: a shape the parser misses, or a note that needs `verdicts: none` or no_verdict_notes", e.ID, n)
			case rows > 0 && noVerdicts(e, n):
				t.Errorf("%s: %s is marked as stating no verdicts but parses %d verdict rows", e.ID, n, rows)
			}
			if got := verdictChanges(note, note); len(got) != 0 {
				t.Errorf("%s: %s differs from itself: %v", e.ID, n, got)
			}
			if got := verdictChanges(note, jitterDurations(note)); len(got) != 0 {
				t.Errorf("%s: %s: moved durations read as verdict changes: %v", e.ID, n, got)
			}
		}
	}
}

func TestVerdictChangesNormalisesDurationsInTheVerdictCell(t *testing.T) {
	a := "| cell | outcome |\n|---|---|\n| x | refused in 2.09s: no packet |\n| y | logged in and ran them in 1m12.9s |\n| z | ok in 1h2m |\n"
	b := "| cell | outcome |\n|---|---|\n| x | refused in 320ms: no packet |\n| y | logged in and ran them in 40ms |\n| z | ok in 3s |\n"
	if got := verdictChanges(a, b); len(got) != 0 {
		t.Fatalf("durations are not verdicts: %v", got)
	}
	c := strings.Replace(b, "refused in 320ms", "accepted in 320ms", 1)
	if got := verdictChanges(a, c); len(got) != 1 {
		t.Fatalf("a changed word is a verdict change: %v", got)
	}
}

func TestVerdictRowsRecogniseTheColumnsTheNotesUse(t *testing.T) {
	for _, hdr := range []string{"against the docs", "agrees with decision 51", "agrees with decision 50", "SSH result", "result", "held"} {
		old := "| a | claim | " + hdr + " |\n|---|---|---|\n| r1 | c | yes |\n"
		now := strings.Replace(old, "yes", "no", 1)
		got := verdictChanges(old, now)
		if len(got) != 1 {
			t.Errorf("column %q: want one change, got %v", hdr, got)
		}
	}
}

func TestVerdictRowsReadBoldVerdictsInProse(t *testing.T) {
	old := "### (d) thing\n\n  - **(d) FAIL**: PASS iff saved.\n  - **(c) PASS**: ok.\n\n### (e) next\n\n**PASS.** the file changed\n"
	now := strings.Replace(old, "**(d) FAIL**", "**(d) PASS**", 1)
	got := verdictChanges(old, now)
	if len(got) != 1 || !strings.Contains(got[0], "FAIL -> PASS") {
		t.Fatalf("a bold bullet verdict must be compared: %v", got)
	}
	got = verdictChanges(old, strings.Replace(old, "**PASS.** the file", "**FAIL.** the file", 1))
	if len(got) != 1 || !strings.Contains(got[0], "PASS -> FAIL") {
		t.Fatalf("a bold prose verdict under a heading must be compared: %v", got)
	}
}

func TestVerdictRowsKeyByHeadingAndHeader(t *testing.T) {
	// Two tables share a header and a first cell: a row of the second flipping is that row, not the first.
	old := "### one\n\n| cell | outcome |\n|---|---|\n| a | PASS |\n\n### two\n\n| cell | outcome |\n|---|---|\n| a | PASS |\n"
	now := strings.Replace(old, "| a | PASS |\n", "| a | FAIL |\n", 2)
	now = strings.Replace(now, "| a | FAIL |\n", "| a | PASS |\n", 1)
	got := verdictChanges(old, now)
	if len(got) != 1 || !strings.Contains(got[0], "two") {
		t.Fatalf("the change belongs to the table under heading two: %v", got)
	}
	// A row moving to the other table is an add and a remove, not a pairing by order.
	if got := verdictChanges(old, strings.Replace(old, "### two", "### three", 1)); len(got) != 2 {
		t.Fatalf("a renamed heading is a removed and an added row: %v", got)
	}
}
