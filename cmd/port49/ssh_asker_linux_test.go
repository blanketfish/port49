package main

import "testing"

// The parent is field 4 of /proc/<pid>/stat, counted from the last ')' since
// comm may hold spaces and ')'; any form that is not that is an error, never a
// pid (review M4).
func TestParentFromStat(t *testing.T) {
	for stat, want := range map[string]int{
		"123 (sh) S 456 123 123 0 -1\n": 456,
		"123 (a b) c) S 789 1 1 0\n":    789,
		"123 (x) S 1 1 1 0\n":           1,
	} {
		if got, err := parentFromStat([]byte(stat)); err != nil || got != want {
			t.Errorf("%q: got %d, %v; want %d", stat, got, err, want)
		}
	}
	for _, stat := range []string{"", "123 sh S 456 1", "123 (sh)", "123 (sh) S", "123 (sh) S notapid 1"} {
		if got, err := parentFromStat([]byte(stat)); err == nil {
			t.Errorf("%q: got %d, want an error", stat, got)
		}
	}
}
