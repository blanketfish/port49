// Package docgen holds what the documentation site is generated and checked from.
package docgen

import (
	"fmt"
	"regexp"
	"strings"
)

// LabRow is one row of the spec's §15 lab register.
type LabRow struct {
	ID   string
	Open bool
	// Claim and Status are the row's second and last cells as the spec writes them.
	Claim, Status string
}

var labID = regexp.MustCompile(`^L[0-9]+[a-z]?$`)

// LabRegister parses the table under "## 15. Lab register". A row is open unless its Status cell (the
// last one) begins "closed" or "**closed**".
func LabRegister(spec []byte) (map[string]LabRow, error) {
	rows := map[string]LabRow{}
	in := false
	for _, line := range strings.Split(string(spec), "\n") {
		if strings.HasPrefix(line, "## ") {
			if in {
				break
			}
			in = strings.HasPrefix(line, "## 15. Lab register")
			continue
		}
		if !in || !strings.HasPrefix(line, "|") {
			continue
		}
		cells := splitCells(line)
		if len(cells) < 2 {
			continue
		}
		id := strings.TrimSpace(strings.ReplaceAll(cells[0], "**", ""))
		if !labID.MatchString(id) {
			continue // the header and the separator
		}
		if _, dup := rows[id]; dup {
			return nil, fmt.Errorf("lab register: %s appears twice", id)
		}
		status := strings.TrimPrefix(strings.TrimSpace(cells[len(cells)-1]), "**")
		rows[id] = LabRow{ID: id, Open: !strings.HasPrefix(status, "closed"),
			Claim: strings.TrimSpace(cells[1]), Status: strings.TrimSpace(cells[len(cells)-1])}
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("lab register: no rows under \"## 15. Lab register\"")
	}
	return rows, nil
}

// splitCells splits a table row on every "|" not preceded by a backslash. The leading and trailing
// pipes yield no cell.
func splitCells(line string) []string {
	line = strings.TrimSpace(line)
	line = strings.TrimPrefix(line, "|")
	var cells []string
	var cur strings.Builder
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == '\\' && i+1 < len(line) && line[i+1] == '|':
			cur.WriteByte('|')
			i++
		case c == '|':
			cells = append(cells, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		cells = append(cells, cur.String())
	}
	return cells
}

var noteLead = regexp.MustCompile(`^L[0-9]+[a-z]?$`)

// NoteParts splits a results note's file name, "L4-L5-error-juniper_vsrx.md", into the lab IDs it
// leads with and the rest of its name split on "-".
func NoteParts(name string) (ids, rest []string) {
	segs := strings.Split(strings.TrimSuffix(name, ".md"), "-")
	i := 0
	for i < len(segs) && noteLead.MatchString(segs[i]) {
		ids = append(ids, segs[i])
		i++
	}
	return ids, segs[i:]
}

// MatchNote returns the candidate that owns the note: one whose "-"-separated segments occur as a
// contiguous run anywhere in the note's name after its lab IDs. The longest candidate wins, so
// juniper_vjunos never takes a juniper_vjunos-router note.
func MatchNote(name string, candidates []string) (string, bool) {
	_, rest := NoteParts(name)
	best := ""
	for _, c := range candidates {
		if len(c) > len(best) && hasRun(rest, strings.Split(c, "-")) {
			best = c
		}
	}
	return best, best != ""
}

func hasRun(hay, needle []string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		ok := true
		for j, n := range needle {
			if hay[i+j] != n {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
