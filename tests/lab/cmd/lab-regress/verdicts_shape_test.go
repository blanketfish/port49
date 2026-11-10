package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSplitRowKeepsAnEscapedPipeInItsCell(t *testing.T) {
	got := splitRow("| a | `x \\| y` | d |")
	if len(got) != 3 || got[1] != "`x \\| y`" {
		t.Fatalf("an escaped pipe belongs to its cell: %q", got)
	}
}

// Every table row of every manifest note has as many cells as its header: a row that splits wrongly puts its
// verdict column onto a fragment of another cell and hides the real verdict.
func TestEveryManifestTableRowHasAsManyCellsAsItsHeader(t *testing.T) {
	entries, err := loadManifest("../../regress.yaml", specPath)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range entries {
		for _, n := range e.Notes {
			if seen[n] {
				continue
			}
			seen[n] = true
			raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", n))
			if err != nil {
				t.Fatal(err)
			}
			width, fenced := 0, false
			for i, ln := range strings.Split(string(raw), "\n") {
				if strings.HasPrefix(strings.TrimSpace(ln), "```") {
					fenced = !fenced
				}
				cells := splitRow(ln)
				switch {
				case fenced || cells == nil:
					width = 0
				case width == 0:
					width = len(cells)
				case len(cells) > width && !isSeparator(cells):
					// A row may stop short (markdown allows it); one with more cells split a cell in two.
					t.Errorf("%s:%d: %d cells under a header of %d", n, i+1, len(cells), width)
				}
			}
		}
	}
}

func TestAHashLineInsideACodeFenceIsNotAHeading(t *testing.T) {
	old := "### real\n\n```\n# L66 baseline: a known_hosts dump\n```\n\n| cell | outcome |\n|---|---|\n| a | PASS |\n"
	now := strings.Replace(old, "| a | PASS |", "| a | FAIL |", 1)
	got := verdictChanges(old, now)
	if len(got) != 1 || !strings.Contains(got[0], `"real"`) {
		t.Fatalf("the row sits under the heading `real`, not the fenced comment: %v", got)
	}
	// And a fenced table-looking line is not a row.
	fencedOnly := "```\n| cell | outcome |\n|---|---|\n| a | PASS |\n```\n"
	if rows := verdictRows(fencedOnly); len(rows) != 0 {
		t.Fatalf("fenced text is not a note's table: %v", rows)
	}
}
