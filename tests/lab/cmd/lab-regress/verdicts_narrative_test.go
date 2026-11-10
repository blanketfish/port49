package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/decision"
)

// A narrative column (observed, the device, what the device saw, any other free-text column) is compared by
// the verdict words it holds, not by its text: each pair below changes a verdict word and must flag.
func TestNarrativeColumnsFlagAChangedVerdictWord(t *testing.T) {
	for _, c := range []struct{ name, note, a, b string }{
		{"L43 directory", "| cell | observed |\n|---|---|\n| b | directory: identity_ambiguous |\n", "identity_ambiguous", "no server answered"},
		{"L35 records", "| step | observed |\n|---|---|\n| 3 | refused in 1s; records [deny credential_revoked] |\n", "credential_revoked", "store_unavailable"},
		{"L37 records", "| step | the device |\n|---|---|\n| 3 | refused; records [deny credential_revoked] |\n", "credential_revoked", "store_unavailable"},
		{"L55 second part", "| step | observed |\n|---|---|\n| 4 | accepted; refused |\n", "accepted; refused", "accepted"},
		{"L43 LDAP code", "| user | observed |\n|---|---|\n| a | bind: LDAP Result Code 13 confidentiality |\n", "Code 13", "Code 8"},
		{"not reached", "| cell | what the device saw |\n|---|---|\n| a | reached the shell |\n", "reached", "not reached"},
		{"free column", "| cell | outcome | `configure terminal` |\n|---|---|---|\n| a | ran | ran |\n", "| ran |\n", "| refused |\n"},
	} {
		if !flips(t, c.note, c.a, c.b) {
			t.Errorf("%s: a changed verdict word did not flag", c.name)
		}
	}
}

// What a rerun moves in a narrative cell and no normaliser can tell from a real difference (a purge count, a
// byte count, a step count) does not flag while the cell's verdict words stay the same.
func TestNarrativeColumnsIgnoreFiguresAndWording(t *testing.T) {
	for _, c := range []struct{ name, note, a, b string }{
		{"purge count", "| step | observed |\n|---|---|\n| 4 | port49d: purged 153 token(s); refused |\n", "purged 153", "purged 160"},
		{"byte count", "| case | observed | against the docs |\n|---|---|---|\n| a | 4123 bytes sent, reply accepted | agrees |\n", "4123 bytes", "4188 bytes"},
		{"wording", "| step | the device |\n|---|---|\n| 1 | ran show version, 3 steps |\n", "3 steps", "5 steps"},
	} {
		if flips(t, c.note, c.a, c.b) {
			t.Errorf("%s: a narrative figure flagged", c.name)
		}
	}
}

// How many times a verdict word occurs is how many connections a device opened or retried (L37's
// "connections:" lists), so only a word appearing or disappearing flags.
func TestNarrativeColumnsCompareTheSetOfVerdictWords(t *testing.T) {
	note := "| step | observed |\n|---|---|\n| 2 | to .1: refused; to .2: accepted; to .2: accepted |\n"
	if flips(t, note, "to .2: accepted; to .2: accepted", "to .2: accepted; to .1: refused; to .2: accepted; to .2: accepted") {
		t.Error("more retries of the same answers are not a verdict change")
	}
	if !flips(t, note, "to .1: refused; ", "") {
		t.Error("a refusal that disappears must flag")
	}
}

// "no" before a word is a determiner ("no error", "no data after the server's first data"), which comes and
// goes with what a capture held; a bare "no" is an answer and flags. "the reset's packet" is a possessive noun.
func TestDeterminerNoAndPossessivesAreNotVerdictWords(t *testing.T) {
	// the before-cell holds no other "no", so a "no" read as a verdict word would change its set
	note := "| cell | observed |\n|---|---|\n| c | login ok true, device sent 9 bytes |\n"
	if flips(t, note, "device sent 9 bytes", "device sent no data after the server's first data") {
		t.Error("a determiner `no` is not a verdict word")
	}
	if flips(t, note, "device sent 9 bytes", "the reset's packet was type=acct") {
		t.Error("a possessive `reset's` is not a verdict word")
	}
	bare := "| cell | observed |\n|---|---|\n| c | SNI sent: yes |\n"
	if !flips(t, bare, "yes |", "no |") {
		t.Error("a bare yes -> no must flag")
	}
}

// deny, permit, "logged in" and "timed out" are verdict words; a multi-word one matches as a whole phrase.
func TestDenyPermitLoggedInTimedOutAreVerdictWords(t *testing.T) {
	note := "| step | observed |\n|---|---|\n| 1 | the session logged in, show version printed |\n"
	if !flips(t, note, "logged in", "timed out") {
		t.Error(`"logged in" -> "timed out" must flag`)
	}
	rec := "| step | observed |\n|---|---|\n| 2 | record [permit x] |\n"
	if !flips(t, rec, "[permit x]", "[deny x]") {
		t.Error("permit -> deny must flag")
	}
	for in, want := range map[string]string{"logged into the box": "{}", "Logged  In": "{logged in}", "timed outright": "{}"} {
		if got := verdictTokens(in); got != want {
			t.Errorf("verdictTokens(%q) = %s, want %s: a phrase matches whole", in, got, want)
		}
	}
}

// Every reason code of internal/decision/reasons.go is a verdict word: swapping one for another flags.
func TestEveryReasonCodeIsAVerdictWord(t *testing.T) {
	rs := decision.Reasons()
	for i, r := range rs {
		other := rs[(i+1)%len(rs)]
		note := "| step | observed |\n|---|---|\n| 1 | the record: " + string(r) + " |\n"
		if !flips(t, note, string(r)+" |", string(other)+" |") {
			t.Errorf("%s -> %s in a narrative cell did not flag", r, other)
		}
	}
}

// A narrative change that leaves the verdict words alone does not fail the entry; it is printed for a person.
func TestANarrativeChangeIsPrintedAndDoesNotFail(t *testing.T) {
	note := "## Observation\n\n| step | observed |\n|---|---|\n| 4 | port49d: purged 153 token(s); refused |\n"
	gitRepo(t, map[string]string{"results/L35-x.md": note})
	if err := os.WriteFile("results/L35-x.md", []byte(strings.Replace(note, "153", "160", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	was := narrativeOut
	narrativeOut = &out
	t.Cleanup(func() { narrativeOut = was })
	if err := checkVerdicts(Entry{ID: "L35", Notes: []string{"results/L35-x.md"}}); err != nil {
		t.Fatalf("a narrative change is not a verdict change: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "L35") || !strings.Contains(got, "narrative changed") || !strings.Contains(got, "purged 160") {
		t.Fatalf("the narrative change must be printed, naming the entry and the new text: %q", got)
	}
}

// A parenthetical in a verdict column is narrative: L29-reload's vJunos rows carry "(the reset's packet:
// `type=acct`)" on some runs and not others while the verdict before it stays the same.
func TestAParentheticalInAVerdictColumnIsNarrative(t *testing.T) {
	h := "| step | outcome |\n|---|---|\n"
	bare := h + "| first `show version` after the change | printed its output in 200ms |\n"
	with := h + "| first `show version` after the change | printed its output in 200ms (the reset's packet: `type=acct`) |\n"
	if got := verdictChanges(bare, with); len(got) != 0 {
		t.Fatalf("a parenthetical that comes and goes is not a verdict change: %v", got)
	}
	if !flips(t, with, "printed its output in 200ms", "refused in 200ms") {
		t.Error("the verdict before the parenthetical must still be compared on its text")
	}
	inner := h + "| a | logged in (the second attempt refused) |\n"
	if !flips(t, inner, "attempt refused)", "attempt accepted)") {
		t.Error("a verdict word inside the parenthetical must still flag")
	}
	code := h + "| a | refused `^show( *\\|.*)?$` |\n"
	if !flips(t, code, "( *", "(x*") {
		t.Error("parentheses inside a code span are the cell's text, not a parenthetical")
	}
}

// A bare yes/no matrix cell compares the same on its text and on its verdict words, so a narrative column of a
// matrix row is not promoted to a verdict column: the row that grows "no (the second try)" next run reads as
// the same answer, and a flipped cell still flags.
func TestAMatrixRowsNarrativeCellIsComparedByItsVerdictWords(t *testing.T) {
	note := "| cell | outcome | observed |\n|---|---|---|\n| a | yes | no |\n"
	if got := verdictChanges(note, strings.Replace(note, "| no |", "| no (the second try) |", 1)); len(got) != 0 {
		t.Errorf("the same answer with a note beside it is not a verdict change: %v", got)
	}
	if !flips(t, note, "| no |", "| yes |") {
		t.Error("a flipped matrix cell must flag")
	}
}

// L22's `reply` is port49's reply: its role strings are compared on their text.
func TestReplyColumnComparesRoleStrings(t *testing.T) {
	note := "| level | reply | observed |\n|---|---|---|\n| 15 | shell:roles*network-admin | opened |\n"
	if !flips(t, note, "network-admin", "network-operator") {
		t.Error("a changed role in `reply` must flag")
	}
}
