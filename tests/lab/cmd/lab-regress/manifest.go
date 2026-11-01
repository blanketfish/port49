package main

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/blanketfish/port49/internal/yamlfault"
	"gopkg.in/yaml.v3"
)

type Entry struct {
	ID string `yaml:"id"`
	// Target is the Make target an operator runs to do the same entry by hand
	// (make lab-regions); the runner itself always execs the one shared binary.
	Target          string            `yaml:"target"`
	Run             string            `yaml:"run"`
	Platforms       string            `yaml:"platforms"`
	Rows            []string          `yaml:"rows"`
	Env             map[string]string `yaml:"env"`
	Notes           []string          `yaml:"notes"`
	MeasuredMinutes float64           `yaml:"measured_minutes"`
	// TimeoutMinutes is the binary's -test.timeout; zero means 120 minutes a
	// platform, make lab's budget (timeoutFor).
	TimeoutMinutes int `yaml:"timeout_minutes"`
}

// Exclusion records a closed row the runner does not rerun, and why. It is
// data the loader checks and the closed-row test reads, so the gap is in the
// repository and not only in a report.
type Exclusion struct {
	Rows   []string `yaml:"rows"`
	Reason string   `yaml:"reason"`
}

type Manifest struct {
	Entries  []Entry     `yaml:"entries"`
	Excluded []Exclusion `yaml:"excluded"`
}

func loadManifest(path, spec string) ([]Entry, error) {
	m, err := loadManifestFile(path, spec)
	return m.Entries, err
}

func loadManifestFile(path, spec string) (Manifest, error) {
	var m Manifest
	raw, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return m, fmt.Errorf("%s: %w", path, err)
	}
	if err := yamlfault.OneDocument(dec); err != nil {
		return m, fmt.Errorf("%s: %w", path, err)
	}
	specText, err := os.ReadFile(spec)
	if err != nil {
		return m, err
	}
	seen := map[string]bool{}
	for _, e := range m.Entries {
		if e.ID == "" || e.Run == "" {
			return m, fmt.Errorf("%s: an entry needs an id and a run pattern (%+v)", path, e)
		}
		if seen[e.ID] {
			return m, fmt.Errorf("%s: duplicate entry id %s (-only would run both)", path, e.ID)
		}
		seen[e.ID] = true
		names := strings.Split(e.Env["PORT49_LAB_REMEASURE"], ",")
		for _, row := range e.Rows {
			if !rowClosed(string(specText), row) {
				continue
			}
			// A guard entry belongs to a row by its leading L<N> (registerRowClosed),
			// so L26b and L26c name L26 as L22-carried names L22; L5 never names L53.
			belongs := regexp.MustCompile(`^` + regexp.QuoteMeta(row) + `(\D|$)`)
			if !slices.ContainsFunc(names, belongs.MatchString) {
				return m, fmt.Errorf("%s: row %s is closed, so env.PORT49_LAB_REMEASURE must name it "+
					"(tests/lab guardClosed refuses the run otherwise)", e.ID, row)
			}
		}
	}
	for _, x := range m.Excluded {
		if len(x.Rows) == 0 || strings.TrimSpace(x.Reason) == "" {
			return m, fmt.Errorf("%s: an exclusion names its rows and gives a reason (%+v)", path, x)
		}
	}
	return m, nil
}

// closedRows lists the rows of spec §15 whose Status begins "closed".
func closedRows(spec string) []string {
	var out []string
	re := regexp.MustCompile(`^\| \*\*(L\d+)\*\* \|`)
	for _, ln := range strings.Split(spec, "\n") {
		if m := re.FindStringSubmatch(ln); m != nil && rowClosed(spec, m[1]) {
			out = append(out, m[1])
		}
	}
	return out
}

// rowClosed is tests/lab's registerRowClosed (harness_test.go:3371), which a
// command cannot import from a test file: the row's last cell starts "closed".
func rowClosed(spec, id string) bool {
	for _, ln := range strings.Split(spec, "\n") {
		if strings.HasPrefix(ln, "| **"+id+"** |") {
			cells := strings.Split(ln, "|")
			return len(cells) >= 3 && strings.HasPrefix(strings.TrimSpace(cells[len(cells)-2]), "closed")
		}
	}
	return false
}

// patternMatches reports the tests run matches, and the alternatives of an
// anchored ^(a|b)$ or ^a$ pattern that match none.
func patternMatches(run string, tests []string) (matched, unmatched []string) {
	re := regexp.MustCompile(run)
	for _, t := range tests {
		if re.MatchString(t) {
			matched = append(matched, t)
		}
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(run, "^"), "$")
	inner = strings.TrimSuffix(strings.TrimPrefix(inner, "("), ")")
	for _, alt := range strings.Split(inner, "|") {
		if !slices.Contains(tests, alt) {
			unmatched = append(unmatched, alt)
		}
	}
	return matched, unmatched
}

// measuredTotal is the entries' last measured wall time, in minutes; an entry
// that failed its last run has none and counts zero.
func measuredTotal(entries []Entry) float64 {
	var total float64
	for _, e := range entries {
		total += e.MeasuredMinutes
	}
	return total
}
