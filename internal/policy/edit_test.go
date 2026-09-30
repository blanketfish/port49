package policy

import (
	"strings"
	"testing"
)

// Offboarding a machine subject is one command (spec §12; decision 2's cost):
// every grant row goes, then the subject block, and the result still loads
// and still passes the tests that did not name it.
func TestRemoveSubjectDeletesItsRowsAndItsBlock(t *testing.T) {
	out, r, err := RemoveSubject(spec11Raw(t), "svc_oxidized")
	if err != nil {
		t.Fatal(err)
	}
	if r.Grants != 1 || r.Tests != 3 {
		t.Fatalf("removed %+v, want one grant row and three tests", r)
	}
	if strings.Contains(string(out), "name: svc_oxidized") || strings.Contains(string(out), "subject: svc_oxidized") ||
		strings.Contains(string(out), "system:serviceaccount") {
		t.Fatalf("the subject is still named:\n%s", out)
	}
	if !strings.Contains(string(out), "# Spec §11's complete policy example") {
		t.Fatalf("comments must survive the edit:\n%s", out)
	}
	p := spec11(t, out)
	if _, ok := p.Subject("svc_oxidized"); ok {
		t.Fatal("the subject block must go with its last grant")
	}
	for _, res := range p.RunTests(noon) {
		if !res.Pass {
			t.Errorf("a remaining test fails: %+v", res.Test)
		}
	}
	if _, ok := p.Subject("noc_tier1"); !ok || len(p.Grants("noc_tier1")) != 2 {
		t.Fatal("nobody else's rows are touched")
	}
}

// A test naming the subject by one of its identities goes with it: left, it
// would load and quietly become a no_grants_matched deny.
func TestRemoveSubjectTakesTestsNamingItsIdentities(t *testing.T) {
	raw := string(spec11Raw(t)) + `  - {principal: "system:serviceaccount:netops:oxidized", device: leaf-01,
     command: "show version", expect: permit}
`
	out, r, err := RemoveSubject([]byte(raw), "svc_oxidized")
	if err != nil {
		t.Fatal(err)
	}
	if r.Tests != 4 || strings.Contains(string(out), "system:serviceaccount") || !onlyDeletions(raw, string(out)) {
		t.Fatalf("removed %+v:\n%s", r, out)
	}
}

func TestRemoveSubjectRefusesAnUndeclaredSubject(t *testing.T) {
	if _, _, err := RemoveSubject(spec11Raw(t), "svc_nobody"); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("%v", err)
	}
}

// The output is the pull request, so it differs from the input only by the
// removed items' lines: every other byte, blank lines and column alignment
// included, is the operator's (review of Task 19, I1).
func TestRemoveSubjectCutsOnlyTheRemovedLines(t *testing.T) {
	raw := spec11Raw(t)
	out, _, err := RemoveSubject(raw, "svc_oxidized")
	if err != nil {
		t.Fatal(err)
	}
	// spec11.yaml lines 101-102 (the subject block), 108 (its grant row),
	// 116-119 (two of its tests, wrapped, one with a trailing comment), and
	// 124 (its session test).
	var want []string
	for i, line := range strings.SplitAfter(string(raw), "\n") {
		if n := i + 1; (n >= 101 && n <= 102) || n == 108 || (n >= 116 && n <= 119) || n == 124 {
			continue
		}
		want = append(want, line)
	}
	if string(out) != strings.Join(want, "") {
		t.Fatalf("the output is not the input less the removed lines:\n%s", out)
	}
	for _, name := range []string{"netops_admins", "noc_tier1", "security_ir"} {
		if out, _, err := RemoveSubject(raw, name); err != nil || !onlyDeletions(string(raw), string(out)) {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
	}
}

// A block item removed from between blank lines takes one of them with it, so
// the file does not grow a double gap; the dash on a line of its own and a
// block scalar's blank line go with the item too.
func TestRemoveSubjectCutsABlockItemWhole(t *testing.T) {
	raw := `subjects:
  - {name: a, identity: "user:a", username: a, token_ttl: 60s}

  -
    name: b
    identity:
      - "user:b"
    note: |
      first

      second

  - {name: c, identity: "user:c", username: c, token_ttl: 60s}
grants: []
`
	out, _, err := RemoveSubject([]byte(raw), "b")
	if err != nil {
		t.Fatal(err)
	}
	want := `subjects:
  - {name: a, identity: "user:a", username: a, token_ttl: 60s}

  - {name: c, identity: "user:c", username: c, token_ttl: 60s}
grants: []
`
	if string(out) != want {
		t.Fatalf("got:\n%s", out)
	}
}

// A flow sequence cannot lose an item by deleting lines, and a second YAML
// document would be dropped silently: both are refused, so the operator edits
// by hand rather than receive a file that is not theirs.
func TestRemoveSubjectRefusesWhatItCannotCutByLine(t *testing.T) {
	for name, raw := range map[string]string{
		"flow sequence": "subjects: [{name: a, identity: \"user:a\"}]\n",
		"two documents": "subjects:\n  - {name: a, identity: \"user:a\"}\n---\nfoo: bar\n",
	} {
		if _, _, err := RemoveSubject([]byte(raw), "a"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// onlyDeletions says whether out's lines are a subsequence of in's.
func onlyDeletions(in, out string) bool {
	inLines := strings.SplitAfter(in, "\n")
	i := 0
	for _, line := range strings.SplitAfter(out, "\n") {
		for i < len(inLines) && inLines[i] != line {
			i++
		}
		if i == len(inLines) {
			return false
		}
		i++
	}
	return true
}

// A comment directly above a removed item is the item's label and goes with
// it: left, it would label the row that follows, or dangle at the end of the
// list. A comment set off by a blank line is the section's and stays.
func TestRemoveSubjectTakesTheCommentAboveAnItem(t *testing.T) {
	const raw = `subjects:
  # everyone's subjects
  - {name: y, identity: "app:y", username: y, token_ttl: 60s}
  # robots below

  # the backup robot
  - {name: x, identity: "app:x", username: x, token_ttl: 60s}
  - {name: z, identity: "app:z", username: z, token_ttl: 60s}
grants:
  - {subject: y, scope: all_devices, roles: [r]}
  # x's row, ticket 12
  - {subject: x, scope: all_devices, roles: [r]}
`
	out, _, err := RemoveSubject([]byte(raw), "x")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "backup robot") || strings.Contains(string(out), "ticket 12") ||
		!strings.Contains(string(out), "# everyone's subjects") || !strings.Contains(string(out), "# robots below") ||
		!onlyDeletions(raw, string(out)) {
		t.Fatalf("\n%s", out)
	}
}

// A flow mapping wrapped so its closing brace sits at the dash's indent
// cannot be cut by line, and RemoveSubject says so rather than hand back a
// file with a stray brace in it.
func TestRemoveSubjectRefusesWhatItCannotCutCleanly(t *testing.T) {
	const raw = `subjects:
  - {name: x, identity: "app:x", username: x,
    token_ttl: 60s
  }
  - {name: y, identity: "app:y", username: y, token_ttl: 60s}
`
	if out, _, err := RemoveSubject([]byte(raw), "x"); err == nil || !strings.Contains(err.Error(), "by hand") {
		t.Fatalf("%v\n%s", err, out)
	}
}
