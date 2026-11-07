package docgen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/devicecert"
)

func readSpec(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, "docs/design/2026-08-23-policy-engine-spec.md"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSpecTableReadsTheReasonCodes(t *testing.T) {
	rows, err := SpecTable(readSpec(t), "#### Reason codes")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 || len(rows[0]) < 2 || strings.Trim(rows[0][0], "` ") != "grants_matched" {
		t.Fatalf("first row = %v, want grants_matched", rows)
	}
}

func TestSpecTableKnowsItsHeadingAndItsCells(t *testing.T) {
	spec := []byte("#### Other\n\n| a | b |\n|---|---|\n| x | y |\n\n#### Mine\n\ntext\n\n| h1 | h2 |\n|---|---|\n| `c1` | one \\| two |\n| c2 | d2 |\n\nafter\n\n| z | z |\n|---|---|\n| no | no |\n")
	rows, err := SpecTable(spec, "#### Mine")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0][0] != "`c1`" || rows[0][1] != `one \| two` || rows[1][1] != "d2" {
		t.Fatalf("rows = %q", rows)
	}
	if _, err := SpecTable(spec, "#### Missing"); err == nil {
		t.Fatal("a missing heading is an error")
	}
}

func TestEveryReasonHasASpecRow(t *testing.T) {
	if _, err := ReasonPage(readSpec(t)); err != nil {
		t.Fatal(err)
	}
}

func TestEverySpecReasonIsACode(t *testing.T) {
	rows, err := SpecTable(readSpec(t), "#### Reason codes")
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, r := range decision.Reasons() {
		known[string(r)] = true
	}
	for _, row := range rows {
		if c := strings.Trim(row[0], "` "); !known[c] {
			t.Errorf("spec row %q is not a decision.Reason", c)
		}
	}
}

func TestReasonPageNamesTheGaps(t *testing.T) {
	spec := []byte("#### Reason codes\n\n| reason | Meaning |\n|---|---|\n| `grants_matched` | ok |\n| `made_up` | nope |\n")
	_, err := ReasonPage(spec)
	if err == nil || !strings.Contains(err.Error(), "made_up") || !strings.Contains(err.Error(), "no_grants_matched") {
		t.Fatalf("err = %v, want both the code with no row and the row with no code", err)
	}
}

func TestEveryRecordFieldHasADescription(t *testing.T) {
	spec := readSpec(t)
	desc, err := LoadDecisionLogDescriptions(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecisionLogPage(spec, desc); err != nil {
		t.Fatal(err)
	}
}

func TestDecisionLogPageNamesTheGaps(t *testing.T) {
	spec := readSpec(t)
	desc, err := LoadDecisionLogDescriptions(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	less := map[string]string{}
	for k, v := range desc {
		if k != "session.username_redacted" {
			less[k] = v
		}
	}
	less["no.such.field"] = "x"
	_, err = DecisionLogPage(spec, less)
	if err == nil || !strings.Contains(err.Error(), "no description for session.username_redacted") ||
		!strings.Contains(err.Error(), "no field for description no.such.field") {
		t.Fatalf("err = %v", err)
	}
}

func TestTheDecisionLogPageNamesEveryTLSOutcome(t *testing.T) {
	desc, err := LoadDecisionLogDescriptions(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	page, err := DecisionLogPage(readSpec(t), desc)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page, "{#tls_outcome}") {
		t.Error("the page has no {#tls_outcome} anchor")
	}
	for _, o := range append([]devicecert.Outcome{devicecert.OK, devicecert.Resumed}, devicecert.Outcomes...) {
		if !strings.Contains(page, "`"+string(o)+"`") {
			t.Errorf("the page does not name the tls_outcome %q", o)
		}
	}
	for _, f := range []string{"session.username_redacted", "packet_fields.priv_lvl", "credential_sha256"} {
		if !strings.Contains(page, f) {
			t.Errorf("the page does not mention %s", f)
		}
	}
}
