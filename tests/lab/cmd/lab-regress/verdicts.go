package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// A verdict table is a markdown table whose header has an "outcome" or "verdict"
// column (the harness writes "| cell | outcome | elapsed |" and
// "| Cell | Verdict | Observation |"). Its rows are keyed by the first cell.
// Tables without such a column (timings, captures) are not compared.

type verdictRow struct{ key, verdict string }

func splitRow(ln string) []string {
	ln = strings.TrimSpace(ln)
	if !strings.HasPrefix(ln, "|") {
		return nil
	}
	cells := strings.Split(strings.Trim(ln, "|"), "|")
	for i := range cells {
		cells[i] = strings.TrimSpace(cells[i])
	}
	return cells
}

func isSeparator(cells []string) bool {
	for _, c := range cells {
		if strings.Trim(c, "-: ") != "" {
			return false
		}
	}
	return len(cells) > 0
}

// verdictRows lists the verdict-table rows of a note in order. A key repeated
// in the note (two tables, one cell name) gets a "#2", "#3" suffix.
func verdictRows(note string) []verdictRow {
	var rows []verdictRow
	seen := map[string]int{}
	col := -1 // the verdict column of the table being read, or -1
	inHeader := false
	for _, ln := range strings.Split(note, "\n") {
		cells := splitRow(ln)
		if cells == nil {
			col, inHeader = -1, false
			continue
		}
		if !inHeader && col == -1 {
			// a candidate header row
			for i, c := range cells {
				if l := strings.ToLower(c); l == "outcome" || l == "verdict" {
					col = i
				}
			}
			inHeader = true
			continue
		}
		if isSeparator(cells) || col < 0 || col >= len(cells) {
			continue
		}
		key := cells[0]
		seen[key]++
		if seen[key] > 1 {
			key = fmt.Sprintf("%s#%d", key, seen[key])
		}
		rows = append(rows, verdictRow{key, strings.Trim(cells[col], "* ")})
	}
	return rows
}

// verdictChanges describes each verdict-table row whose verdict differs between
// the committed note and the rewritten one, and each row added or removed.
func verdictChanges(old, now string) []string {
	oldRows, newRows := verdictRows(old), verdictRows(now)
	was := map[string]string{}
	for _, r := range oldRows {
		was[r.key] = r.verdict
	}
	var out []string
	inNew := map[string]bool{}
	for _, r := range newRows {
		inNew[r.key] = true
		v, ok := was[r.key]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("%s: added (%s)", r.key, r.verdict))
		case v != r.verdict:
			out = append(out, fmt.Sprintf("%s: %s -> %s", r.key, v, r.verdict))
		}
	}
	for _, r := range oldRows {
		if !inNew[r.key] {
			out = append(out, fmt.Sprintf("%s: removed (was %s)", r.key, r.verdict))
		}
	}
	return out
}

// committedNote is the note as HEAD has it; ok is false when HEAD has none
// (a new note has no verdicts to compare against).
func committedNote(path string) (string, bool) {
	out, err := exec.Command("git", "show", "HEAD:"+path).Output()
	if err != nil {
		return "", false
	}
	return string(out), true
}

// checkVerdicts fails an entry whose rewritten notes changed a claim's verdict
// from HEAD's: a flaked or regressed cell must not pass because the binary
// exited 0. It names the entry, the row, and old -> new.
func checkVerdicts(id string, notes []string) error {
	var all []string
	for _, n := range notes {
		old, ok := committedNote(n)
		if !ok {
			continue
		}
		now, err := os.ReadFile(n)
		if err != nil {
			return err
		}
		for _, c := range verdictChanges(old, string(now)) {
			all = append(all, fmt.Sprintf("%s: %s: %s", id, n, c))
		}
	}
	if len(all) > 0 {
		return fmt.Errorf("a claim's verdict changed from HEAD:\n  %s", strings.Join(all, "\n  "))
	}
	return nil
}
