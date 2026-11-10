package main

import (
	"strings"
	"testing"
)

// session-*'s step names carry the wall-clock time the step ran at: the same step on the next run is the same
// row, not a removed and an added one.
func TestARowKeyedByAClockTimeIsTheSameRowNextRun(t *testing.T) {
	h := "| step | observed |\n|---|---|\n"
	a := h + "| 6. `show version` at the ceiling + 10 s (01:55:38.000Z) | refused in 100ms |\n"
	b := h + "| 6. `show version` at the ceiling + 10 s (22:53:51.000Z) | refused in 100ms |\n"
	if got := verdictChanges(a, b); len(got) != 0 {
		t.Fatalf("a clock time in the step name is not a new row: %v", got)
	}
	if !flips(t, b, "refused in", "accepted in") {
		t.Error("the row is still compared")
	}
}

// L3's wire-username rows are keyed by the pool accounts the run logged in as (alice01..alice03, a different
// two each run): a row whose key differs only in an account's number is the same row. A bare number is a
// claim's subject (L8's 30, 31, ... byte lengths), so a removed 30 and an added 31 still flag.
func TestARenumberedPoolAccountIsTheSameRow(t *testing.T) {
	h := "| wire username | verdict | reason | `port` |\n|---|---|---|---|\n"
	a := h + "| `alice03` | deny | `x_y` | vty6 |\n| `alice02` | deny | `x_y` | vty4 |\n"
	b := h + "| `alice01` | deny | `x_y` | vty4 |\n| `alice02` | deny | `x_y` | vty6 |\n"
	if got := verdictChanges(a, b); len(got) != 0 {
		t.Fatalf("the accounts a run drew are not new rows: %v", got)
	}
	c := strings.Replace(b, "| `alice01` | deny |", "| `alice01` | permit |", 1)
	if got := verdictChanges(a, c); len(got) != 1 || !strings.Contains(got[0], "deny") || !strings.Contains(got[0], "permit") {
		t.Fatalf("a renumbered row whose verdict changed is one change, old -> new: %v", got)
	}
	n := "| length | outcome |\n|---|---|\n| 30 | rejected |\n"
	if got := verdictChanges(n, strings.Replace(n, "| 30 |", "| 31 |", 1)); len(got) != 2 {
		t.Fatalf("a bare-number key is the claim's subject: a removed and an added row, got %v", got)
	}
}

// L73's harness marks a connection whose SYN came before the login as the readiness probe's: not part of the
// measured window, and present or not depending on timing.
func TestTheReadinessProbesConnectionIsNotMeasured(t *testing.T) {
	h := "| cell | observed | against the docs |\n|---|---|---|\n"
	a := h + "| j | j2: break-glass ok true; +0.01s to 172.100.100.2:49: syn-ack, ended device-fin | yes |\n"
	b := h + "| j | j2: break-glass ok true; -0.00s to 172.100.100.2:49: syn-ack (opened before the login: the readiness probe's connection), ended device-fin | yes |\n"
	if got := verdictChanges(a, b); len(got) != 0 {
		t.Fatalf("the readiness probe's connection is not a measurement: %v", got)
	}
	if !flips(t, a, "break-glass ok true", "break-glass refused") {
		t.Error("the cell is still compared")
	}
}
