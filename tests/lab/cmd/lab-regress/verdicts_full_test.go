package main

import (
	"strings"
	"testing"
)

// flips reports whether replacing a with b in note changes a verdict.
func flips(t *testing.T, note, a, b string) bool {
	t.Helper()
	if !strings.Contains(note, a) {
		t.Fatalf("the fixture lacks %q", a)
	}
	return len(verdictChanges(note, strings.Replace(note, a, b, 1))) > 0
}

// Each pair is a real change that a cut at the first ':' or ';' collapsed to one value (review 3, finding 1):
// every one must flag.
func TestFullCellsFlagTheRealChanges(t *testing.T) {
	for _, c := range []struct{ name, note, a, b string }{
		{"L29 reason", "| step | outcome | took |\n|---|---|---|\n| next | refused in 2s: `% Authorization denied: Unknown role` | 2s |\n",
			"Unknown role", "this session was not authenticated by port49"},
		{"L43 LDAP code", "| user | result |\n|---|---|\n| a | refused: LDAP Result Code 13 confidentiality |\n", "Code 13", "Code 8"},
		{"L43 directory", "| cell | observed |\n|---|---|\n| b | directory: identity_ambiguous |\n", "identity_ambiguous", "no server answered"},
		{"L35 records", "| step | observed |\n|---|---|\n| 3 | refused in 1s; records [deny credential_revoked] |\n", "credential_revoked", "store_unavailable"},
		{"L55 second part", "| step | observed |\n|---|---|\n| 4 | accepted; refused |\n", "accepted; refused", "accepted"},
		{"L22 reply", "| level | reply | session |\n|---|---|---|\n| 15 | shell:roles*network-admin | x |\n", "network-admin", "network-operator"},
	} {
		if !flips(t, c.note, c.a, c.b) {
			t.Errorf("%s: a real change did not flag", c.name)
		}
	}
}

// A table whose only verdict-looking column is `reply` (port49's input) still compares the device's columns.
func TestEveryColumnAfterTheKeyIsCompared(t *testing.T) {
	l22 := "| attribute | session | identity | `clear counters` | `configure terminal` | inert |\n|---|---|---|---|---|---|\n| a | x | y | ran | refused | no |\n"
	if !flips(t, l22, "| refused |", "| ran |") {
		t.Error("a change in the `configure terminal` column must flag")
	}
	carried := "| reply | session | identity | `clear counters` | `show version` |\n|---|---|---|---|---|\n| shell:roles*a | x | y | ran | ran |\n"
	if !flips(t, carried, "| ran | ran |", "| ran | refused |") {
		t.Error("a change in a table keyed by `reply` must flag")
	}
}

func TestTranscriptAndRationaleColumnsAreLeftOut(t *testing.T) {
	for _, hdr := range []string{"why", "Why", "transcript after port49d stopped", "what the device said"} {
		note := "| cell | outcome | " + hdr + " |\n|---|---|---|\n| a | ran | first text |\n"
		if flips(t, note, "first text", "second text") {
			t.Errorf("column %q is free text and must not be compared", hdr)
		}
		if !flips(t, note, "| ran |", "| refused |") {
			t.Errorf("the outcome beside %q must still be compared", hdr)
		}
	}
}

// Rows an L35-restore rerun moves: etcd revisions, tty names, record order, addresses, ports, temp paths, ids.
func TestRunToRunNoiseDoesNotFlag(t *testing.T) {
	old := "| step | observed |\n|---|---|\n" +
		"| 1 | snapshot at 320; the store at 1000000320; port=vty6; 127.0.0.1:19000 |\n" +
		"| 2 | authorize_command deny; accounting; blob |\n" +
		"| 3 | via port 41234, /tmp/p49l64home1459925485/.ssh/known_hosts, ctx 7Q3KZ9M2XA81BCDE |\n"
	now := "| step | observed |\n|---|---|\n" +
		"| 1 | snapshot at 321; the store at 1000000999; port=tty435; 127.0.0.1:19044 |\n" +
		"| 2 | blob; accounting; authorize_command deny |\n" +
		"| 3 | via port 52999, /tmp/p49l64home99/.ssh/known_hosts, ctx 1A2B3C4D5E6F7G8H |\n"
	if got := verdictChanges(old, now); len(got) != 0 {
		t.Fatalf("run-to-run values are not verdict changes: %v", got)
	}
}

// The tty a login lands on (vty4, tty435) and the round-trip figures of a ping move every run.
func TestTTYNamesAndPingFiguresDoNotFlag(t *testing.T) {
	h := "| user | observed | reason | tty | ping |\n|---|---|---|---|---|\n"
	a := h + "| a | deny | token_not_found | vty4 | rtt min/avg/max/mdev = 40.031/40.110/40.190/0.052 ms |\n"
	b := h + "| a | deny | token_not_found | tty435 | rtt min/avg/max/mdev = 41.091/40.496/41.354/0.469 ms |\n"
	if got := verdictChanges(a, b); len(got) != 0 {
		t.Fatalf("a tty name and a ping figure are not verdicts: %v", got)
	}
}

func TestReadOffAndRulingBulletsAreComparedOnTheirFullText(t *testing.T) {
	note := "### Read off the table\n\n- reached: op url in P (accepted)\n- start shell refused in P and C alike (the bits), reached in R\n" +
		"- explicit anchors: true: refused `show version` (true)\n- **Ruling 15 may close on this run:** true (the control held: true)\n"
	for _, c := range [][2]string{
		{"reached: op url in P (accepted)", "reached: op url in P (refused)"},
		{"refused in P and C alike (the bits)", "refused in P only (the bits)"},
		{"refused `show version` (true)", "refused `show version` (false)"},
		{"(the control held: true)", "(the control held: false)"},
	} {
		if !flips(t, note, c[0], c[1]) {
			t.Errorf("%q -> %q must flag", c[0], c[1])
		}
	}
}

func TestYesNoClaimsInsideSentencesAreVerdicts(t *testing.T) {
	note := "## Observation\n\n- **2. Renew** (the same broker):\n  - Same URI SAN: yes (`[spiffe://x]`); same public key: yes; serial `a` to `b` (new serial: yes).\n" +
		"  - Renewed 9m31s after the daemon started, at 0.66 of the lifetime, and `workload token` exit 0.\n\nThe device rebooted: true.\n"
	for _, c := range [][2]string{{"same public key: yes", "same public key: no"}, {"(new serial: yes)", "(new serial: no)"}, {"rebooted: true", "rebooted: false"}} {
		if !flips(t, note, c[0], c[1]) {
			t.Errorf("%q -> %q must flag", c[0], c[1])
		}
	}
	prose := "## Observation\n\nRenewed 9m31s after the daemon started, at 0.66 of the lifetime.\n"
	if rows := verdictRows(prose); len(rows) != 0 {
		t.Errorf("ordinary prose is not a verdict: %v", rows)
	}
}
