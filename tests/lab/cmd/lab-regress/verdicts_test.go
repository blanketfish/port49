package main

import (
	"strings"
	"testing"
)

const noteL64 = `# L64 — arista_eos

- **Date measured:** 2026-11-07

| cell | outcome | elapsed |
|---|---|---|
| L64a | PASS | 6.7s |
| L64b | PASS | 1m12.9s |
| L64c | PASS | 16.5s |

### L64a: PASS
`

const noteObs = `| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | logged in true after 532ms |
| c | OBSERVED | the store hung |
`

func TestVerdictChangesNone(t *testing.T) {
	// Only elapsed, a date and the prose differ: not a verdict change.
	newer := strings.ReplaceAll(noteL64, "6.7s", "9.9s")
	newer = strings.ReplaceAll(newer, "2026-11-07", "2026-11-09")
	if got := verdictChanges(noteL64, newer); len(got) != 0 {
		t.Fatalf("timing and date changes are not verdict changes: %v", got)
	}
	if got := verdictChanges(noteObs, strings.ReplaceAll(noteObs, "532ms", "700ms")); len(got) != 0 {
		t.Fatalf("an observation cell change is not a verdict change: %v", got)
	}
}

func TestVerdictChangesChangedRow(t *testing.T) {
	newer := strings.Replace(noteL64, "| L64c | PASS |", "| L64c | FAIL |", 1)
	got := verdictChanges(noteL64, newer)
	if len(got) != 1 || !strings.HasPrefix(got[0], "L64c") || !strings.HasSuffix(got[0], ": PASS -> FAIL") {
		t.Fatalf("want one change L64c: PASS -> FAIL, got %v", got)
	}
}

func TestVerdictChangesOtherSpellings(t *testing.T) {
	newer := strings.Replace(noteObs, "| c | OBSERVED |", "| c | **FAIL** |", 1)
	got := verdictChanges(noteObs, newer)
	if len(got) != 1 || got[0] != "c: OBSERVED -> FAIL" {
		t.Fatalf("got %v", got)
	}
}

func TestVerdictChangesAddedAndRemovedRows(t *testing.T) {
	added := noteL64 + "\n| cell | outcome | elapsed |\n|---|---|---|\n| L64e | PASS | 1s |\n"
	got := verdictChanges(noteL64, added)
	if len(got) != 1 || !strings.HasPrefix(got[0], "L64e") || !strings.HasSuffix(got[0], ": added (PASS)") {
		t.Fatalf("an added row is a change: %v", got)
	}
	removed := strings.Replace(noteL64, "| L64b | PASS | 1m12.9s |\n", "", 1)
	got = verdictChanges(noteL64, removed)
	if len(got) != 1 || !strings.HasPrefix(got[0], "L64b") || !strings.HasSuffix(got[0], ": removed (was PASS)") {
		t.Fatalf("a removed row is a change: %v", got)
	}
}

func TestVerdictChangesIgnoresTablesWithoutVerdictColumn(t *testing.T) {
	a := "| FAIL delayed by | SSH login |\n|---|---|\n| 2s | refused |\n"
	b := "| FAIL delayed by | SSH login |\n|---|---|\n| 2s | logged in |\n"
	if got := verdictChanges(a, b); len(got) != 0 {
		t.Fatalf("not a verdict table: %v", got)
	}
}
