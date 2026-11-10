package main

import (
	"strings"
	"testing"
)

func TestInertColumnIsADerivedVerdict(t *testing.T) {
	old := "| attribute | session | inert |\n|---|---|---|\n| a | x | yes |\n"
	if got := verdictChanges(old, strings.Replace(old, "| yes |", "| no |", 1)); len(got) != 1 {
		t.Fatalf("inert yes -> no is a change: %v", got)
	}
}

func TestVerdictCellsNormaliseTimestampsAndLongHex(t *testing.T) {
	old := "| cell | outcome |\n|---|---|\n| a | ok at 2026-11-06T07:53:06Z id bda0e4fbc18e |\n"
	now := "| cell | outcome |\n|---|---|\n| a | ok at 2026-11-09T11:00:00.5+01:00 id 0123456789ab |\n"
	if got := verdictChanges(old, now); len(got) != 0 {
		t.Fatalf("a timestamp and a container id are not verdicts: %v", got)
	}
}
