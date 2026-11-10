package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
)

// A results note states a claim's verdict in one of two shapes:
//
//   - a markdown table whose header has a verdict column: "outcome", "verdict", "result", "SSH result",
//     "held", "against the docs", or "agrees with decision N". Its rows are keyed by the nearest heading,
//     the header row and the first cell.
//   - a bold verdict in prose: "- **(d) FAIL**: ..." or "**PASS.** ...", keyed by the nearest heading and
//     its "(d)" label.
//
// Tables without such a column (timings, captures) are not compared. A note that parses no verdict row is
// refused unless its manifest entry says `verdicts: none` (checkVerdicts), so a shape this parser misses
// fails loudly.

type verdictRow struct{ key, label, verdict string }

// allColumns marks a table whose every column after the first is a verdict (a "Verdict against the control" table).
const allColumns = -2

var (
	verdictColumn = regexp.MustCompile(`^(outcome|verdict|result|ssh result|held|against the docs|agrees with decision \d+)$`)
	// A bold verdict opening a line, bulleted or not: "**(d) FAIL**" or "**PASS.**".
	proseVerdict = regexp.MustCompile(`^(?:[-*]\s+)?\*\*(?:(\([^)]*\))\s+)?(PASS|FAIL|INVALID|OBSERVED|TIMEOUT|SKIPPED)\b[^*]*\*\*`)
	// A qualification note's bullet: "- `token_login` (re-measures L1): **pass**. ..." or "**not_run**".
	cellVerdict = regexp.MustCompile("^- `([^`]+)`[^*]*?: \\*\\*([a-z_]+)\\*\\*")
	// A Go duration, "1m12.9s", "320ms", "1h2m": the numbers a rerun moves.
	durationRe = regexp.MustCompile(`\b\d+(?:\.\d+)?(?:h|ms|µs|us|ns|m|s)(?:\d+(?:\.\d+)?(?:h|ms|µs|us|ns|m|s))*\b`)
)

func splitRow(ln string) []string {
	ln = strings.TrimSpace(ln)
	if !strings.HasPrefix(ln, "|") {
		return nil
	}
	ln = strings.TrimSuffix(strings.TrimPrefix(ln, "|"), "|")
	// An escaped pipe, \|, belongs to its cell (a regexp in a code span, say); only a bare one ends it.
	var cells []string
	var cur strings.Builder
	for i := 0; i < len(ln); i++ {
		switch {
		case ln[i] == '\\' && i+1 < len(ln) && ln[i+1] == '|':
			cur.WriteString(`\|`)
			i++
		case ln[i] == '|':
			cells = append(cells, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(ln[i])
		}
	}
	return append(cells, strings.TrimSpace(cur.String()))
}

func isSeparator(cells []string) bool {
	for _, c := range cells {
		if strings.Trim(c, "-: ") != "" {
			return false
		}
	}
	return len(cells) > 0
}

// verdictText is a verdict cell with the bold marks off and its durations normalised: the harness writes
// how long a step took into the cell ("refused in 2.09s"), and a rerun moves that.
func verdictText(cell string) string {
	return durationRe.ReplaceAllString(strings.Trim(cell, "* "), "<d>")
}

// verdictRows lists the verdict rows of a note in order. A key that repeats gets a "#2", "#3" suffix.
func verdictRows(note string) []verdictRow {
	var rows []verdictRow
	seen := map[string]int{}
	add := func(key, label, verdict string) {
		seen[key]++
		if seen[key] > 1 {
			key = fmt.Sprintf("%s#%d", key, seen[key])
		}
		rows = append(rows, verdictRow{key, label, verdict})
	}
	heading := ""
	col := -1 // the verdict column of the table being read, or -1
	header := ""
	inTable := false
	fenced := false
	for _, ln := range strings.Split(note, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "```") {
			fenced, inTable = !fenced, false
			continue
		}
		if fenced {
			continue // a code fence's lines are quoted text: no heading, row or bullet
		}
		if strings.HasPrefix(ln, "#") {
			heading = strings.TrimSpace(strings.TrimLeft(ln, "#"))
		}
		cells := splitRow(ln)
		if cells == nil {
			inTable = false
			if m := proseVerdict.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
				add(heading+"\x00prose\x00"+m[1], labelFor(heading, strings.TrimSpace(m[1]+" "+m[2])), m[2])
			} else if m := cellVerdict.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
				add(heading+"\x00cell\x00"+m[1], labelFor(heading, m[1]), m[2])
			}
			continue
		}
		if !inTable {
			// the first row of a table is its header
			inTable, col, header = true, -1, strings.Join(cells, "|")
			for i, c := range cells {
				if verdictColumn.MatchString(strings.ToLower(c)) && col < 0 {
					col = i
				}
			}
			if col < 0 && strings.HasPrefix(strings.ToLower(heading), "verdict") {
				col = allColumns // "### Verdict against the control": every column after the first is a verdict
			}
			continue
		}
		if isSeparator(cells) || col == -1 || (col >= 0 && col >= len(cells)) || len(cells) < 2 {
			continue
		}
		verdict := ""
		if col == allColumns {
			verdict = verdictText(strings.Join(cells[1:], " | "))
		} else {
			verdict = verdictText(cells[col])
		}
		add(heading+"\x00"+header+"\x00"+cells[0], labelFor(heading, cells[0]), verdict)
	}
	return rows
}

// labelFor is what a report names a row by: its first cell, and the heading it sits under.
func labelFor(heading, first string) string {
	if heading == "" {
		return first
	}
	return fmt.Sprintf("%s (under %q)", first, heading)
}

// verdictChanges describes each verdict row whose verdict differs between the committed note and the
// rewritten one, and each row added or removed.
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
			out = append(out, fmt.Sprintf("%s: added (%s)", r.label, r.verdict))
		case v != r.verdict:
			out = append(out, fmt.Sprintf("%s: %s -> %s", r.label, v, r.verdict))
		}
	}
	for _, r := range oldRows {
		if !inNew[r.key] {
			out = append(out, fmt.Sprintf("%s: removed (was %s)", r.label, r.verdict))
		}
	}
	return out
}

// noVerdicts is whether a note of the entry states no claim verdict (an observation-only note): the entry
// says `verdicts: none`, or lists the note in no_verdict_notes.
func noVerdicts(e Entry, note string) bool {
	return e.Verdicts == "none" || slices.Contains(e.NoVerdictNotes, note)
}

// gitShow is the note as HEAD has it. Any git failure is an error: git missing, a dubious-ownership
// refusal, a run outside the repository, a note HEAD does not have.
func gitShow(path string) (string, error) {
	out, err := exec.Command("git", "show", "HEAD:"+path).Output()
	if err != nil {
		msg := err.Error()
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			msg += ": " + strings.TrimSpace(string(ee.Stderr))
		}
		return "", fmt.Errorf("%s has no readable copy at HEAD (%s)", path, msg)
	}
	return string(out), nil
}

// checkVerdicts fails an entry whose rewritten notes changed a claim's verdict from HEAD's: a flaked or
// regressed cell must not pass because the binary exited 0. It names the entry, the note, the row, and
// old -> new. Every manifest note belongs to a closed row, so it must exist at HEAD, and a note that parses
// no verdict row is refused unless the entry says `verdicts: none`.
func checkVerdicts(e Entry) error { return checkVerdictsWith(e, gitShow) }

func checkVerdictsWith(e Entry, show func(path string) (string, error)) error {
	var all []string
	for _, n := range e.Notes {
		old, err := show(n)
		if err != nil {
			return fmt.Errorf("%s: %w", e.ID, err)
		}
		raw, err := os.ReadFile(n)
		if err != nil {
			return err
		}
		now := string(raw)
		switch rows := len(verdictRows(now)); {
		case noVerdicts(e, n) && rows > 0:
			return fmt.Errorf("%s: %s is marked as stating no verdicts but parses %d verdict rows: remove the mark", e.ID, n, rows)
		case noVerdicts(e, n):
			continue
		case rows == 0:
			return fmt.Errorf("%s: %s parses no verdict rows: a shape verdicts.go misses, or the entry needs `verdicts: none`", e.ID, n)
		}
		for _, c := range verdictChanges(old, now) {
			all = append(all, fmt.Sprintf("%s: %s: %s", e.ID, n, c))
		}
	}
	if len(all) > 0 {
		return fmt.Errorf("a claim's verdict changed from HEAD:\n  %s", strings.Join(all, "\n  "))
	}
	return nil
}
