package main

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

type Entry struct {
	ID              string            `yaml:"id"`
	Target          string            `yaml:"target"`
	Run             string            `yaml:"run"`
	Platforms       string            `yaml:"platforms"`
	Rows            []string          `yaml:"rows"`
	Env             map[string]string `yaml:"env"`
	Notes           []string          `yaml:"notes"`
	MeasuredMinutes int               `yaml:"measured_minutes"`
}

func loadManifest(path, spec string) ([]Entry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var m struct {
		Entries []Entry `yaml:"entries"`
	}
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	specText, err := os.ReadFile(spec)
	if err != nil {
		return nil, err
	}
	for _, e := range m.Entries {
		names := strings.Split(e.Env["PORT49_LAB_REMEASURE"], ",")
		for _, row := range e.Rows {
			if !rowClosed(string(specText), row) {
				continue
			}
			// A guard entry belongs to a row by its leading L<N> (registerRowClosed),
			// so L26b and L26c name L26 as L22-carried names L22; L5 never names L53.
			belongs := regexp.MustCompile(`^` + regexp.QuoteMeta(row) + `(\D|$)`)
			if !slices.ContainsFunc(names, belongs.MatchString) {
				return nil, fmt.Errorf("%s: row %s is closed, so env.PORT49_LAB_REMEASURE must name it "+
					"(tests/lab guardClosed refuses the run otherwise)", e.ID, row)
			}
		}
	}
	return m.Entries, nil
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
