package main

import (
	"strings"
	"testing"
)

func TestLeadingPhrase(t *testing.T) {
	for _, c := range [][2]string{
		{"`printed its output in 100ms: 'Arista vEOS-lab'`", "printed its output"},
		{"refused in 2.09s: ssh: handshake failed", "refused"},
		{"`exit 0; stdout \"x\"`", "exit 0"},
		{"`2026-11-06T07:53:06Z, 1s before the fixture`", "<t>"},
		{"`the directory's own creation time is 2026-11-06T07:53:06Z; read it`", "the directory's own creation time is <t>"},
		{"`Container port49lab-broker-run-bda0e4fbc18e Creating Container x Created`", "Container port49lab-broker-run-<hex> Creating Container x Created"},
		{"permitted (the version line printed)", "permitted"},
		{"**logged in** in 1m12.9s", "logged in"},
		{"yes", "yes"},
	} {
		if got := leadingPhrase(c[0]); got != c[1] {
			t.Errorf("leadingPhrase(%q) = %q, want %q", c[0], got, c[1])
		}
	}
}

func TestObservedAndReplyColumnsAreComparedByTheirLeadingPhrase(t *testing.T) {
	old := "| step | observed |\n|---|---|\n| 1. login | `printed its output in 100ms: 'v1' ctx_id=abc` |\n| 2. next | `refused in 5ms: reason x at 2026-11-06T07:53:06Z` |\n"
	moved := "| step | observed |\n|---|---|\n| 1. login | `printed its output in 9s: 'v2' ctx_id=zzz` |\n| 2. next | `refused in 7ms: reason y at 2026-11-07T01:02:03Z` |\n"
	if got := verdictChanges(old, moved); len(got) != 0 {
		t.Fatalf("detail after the leading phrase is not a verdict: %v", got)
	}
	flipped := strings.Replace(moved, "refused in 7ms", "printed its output in 7ms", 1)
	if got := verdictChanges(old, flipped); len(got) != 1 || !strings.Contains(got[0], "refused -> printed its output") {
		t.Fatalf("refused -> printed is a change: %v", got)
	}
	reply := "| level | reply | session |\n|---|---|---|\n| 15 | PASS_ADD priv_lvl=15 | x |\n"
	if got := verdictChanges(reply, strings.Replace(reply, "PASS_ADD priv_lvl=15", "FAIL", 1)); len(got) != 1 {
		t.Fatalf("the reply column is a verdict column: %v", got)
	}
}

// A step's outcome cell carries run-to-run detail after its verdict ("(the reset's packet: type=acct)" is there
// in some runs and not in others), so the verdict columns are read by their leading phrase too.
func TestOutcomeCellsAreReadByTheirLeadingPhrase(t *testing.T) {
	old := "| step | outcome |\n|---|---|\n| a | printed its output in 200ms (the reset's packet: `type=acct`) |\n"
	now := "| step | outcome |\n|---|---|\n| a | printed its output in 100ms |\n"
	if got := verdictChanges(old, now); len(got) != 0 {
		t.Fatalf("detail after the leading phrase is not a verdict: %v", got)
	}
	if got := verdictChanges(old, strings.Replace(old, "printed its output", "refused", 1)); len(got) != 1 {
		t.Fatalf("printed -> refused is a change: %v", got)
	}
}

func TestAReadOffBulletWithNoVerdictWordIsProse(t *testing.T) {
	note := "### Read off the table\n\n- `ſhow version` shows that the CLI refuses a keystroke\n- claim: true\n"
	if rows := verdictRows(note); len(rows) != 1 {
		t.Fatalf("only the bullet that states a verdict is a row: %v", rows)
	}
	if got := verdictChanges(note, strings.Replace(note, "refuses a keystroke", "rings the bell", 1)); len(got) != 0 {
		t.Fatalf("rewording prose is not a change: %v", got)
	}
}

func TestInertColumnIsADerivedVerdict(t *testing.T) {
	old := "| attribute | session | inert |\n|---|---|---|\n| a | x | yes |\n"
	if got := verdictChanges(old, strings.Replace(old, "| yes |", "| no |", 1)); len(got) != 1 {
		t.Fatalf("inert yes -> no is a change: %v", got)
	}
}

func TestAPrimaryColumnBeatsAnObservedOne(t *testing.T) {
	old := "| cell | claim | observed | against the docs |\n|---|---|---|---|\n| a | c | noisy 1 | agrees |\n"
	if got := verdictChanges(old, strings.Replace(old, "noisy 1", "noisy 2", 1)); len(got) != 0 {
		t.Fatalf("the observed column is not read when the table has a verdict column: %v", got)
	}
	if got := verdictChanges(old, strings.Replace(old, "| agrees |", "| differs |", 1)); len(got) != 1 {
		t.Fatalf("against the docs is read: %v", got)
	}
}

func TestVerdictCellsNormaliseTimestampsAndLongHex(t *testing.T) {
	old := "| cell | outcome |\n|---|---|\n| a | ok at 2026-11-06T07:53:06Z id bda0e4fbc18e |\n"
	now := "| cell | outcome |\n|---|---|\n| a | ok at 2026-11-09T11:00:00.5+01:00 id 0123456789ab |\n"
	if got := verdictChanges(old, now); len(got) != 0 {
		t.Fatalf("a timestamp and a container id are not verdicts: %v", got)
	}
}
