package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const specPath = "../../../../docs/design/2026-08-23-policy-engine-spec.md"

func TestLoadManifestRefusesAnUnknownKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.yaml")
	os.WriteFile(p, []byte("entries:\n  - {id: L10, run: x, notez: []}\n"), 0o600)
	if _, err := loadManifest(p, specPath); err == nil || !strings.Contains(err.Error(), "notez") {
		t.Fatalf("an unknown key must be refused by name: %v", err)
	}
}

func TestLoadManifestRefusesAClosedRowWithoutRemeasure(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.yaml")
	os.WriteFile(p, []byte("entries:\n  - {id: L10, run: '^TestL10ServiceAndAttributeSpellings$', rows: [L10]}\n"), 0o600)
	if _, err := loadManifest(p, specPath); err == nil || !strings.Contains(err.Error(), "PORT49_LAB_REMEASURE") {
		t.Fatalf("a closed row with no PORT49_LAB_REMEASURE fails at guardClosed; refuse it here: %v", err)
	}
}

func TestTheCommittedManifestLoads(t *testing.T) {
	if _, err := loadManifest("../../regress.yaml", specPath); err != nil {
		t.Fatal(err)
	}
}

// Every alternative of every pattern names at least one test, and no
// pattern matches a test its alternatives do not name exactly.
func TestEveryManifestPatternMatchesATest(t *testing.T) {
	entries, err := loadManifest("../../regress.yaml", specPath)
	if err != nil {
		t.Fatal(err)
	}
	var tests []string
	files, _ := filepath.Glob("../../*.go")
	re := regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]*)\(`)
	for _, f := range files {
		b, _ := os.ReadFile(f)
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			tests = append(tests, m[1])
		}
	}
	for _, e := range entries {
		matched, empty := patternMatches(e.Run, tests)
		if len(empty) > 0 {
			t.Errorf("%s: alternative(s) %v match no test", e.ID, empty)
		}
		for _, m := range matched {
			if !strings.Contains(e.Run, m) {
				t.Errorf("%s: %q also matches %s, which it does not name", e.ID, e.Run, m)
			}
		}
	}
}

func TestTheStopSentinelStopsBeforeTheNextEntry(t *testing.T) {
	dir := t.TempDir()
	stop := filepath.Join(dir, "STOP")
	var ran []string
	r := &runner{stopPath: stop, exec: func(e Entry) error {
		ran = append(ran, e.ID)
		os.WriteFile(stop, nil, 0o600) // the operator asks to stop during the first entry
		return nil
	}}
	rep := r.runAll([]Entry{{ID: "a"}, {ID: "b"}})
	if len(ran) != 1 || ran[0] != "a" || rep.Stopped != "b" {
		t.Fatalf("ran %v, stopped before %q; the running entry finishes and the next never starts", ran, rep.Stopped)
	}
}

func TestAFailedEntryStopsTheRun(t *testing.T) {
	r := &runner{stopPath: filepath.Join(t.TempDir(), "none"), exec: func(e Entry) error {
		if e.ID == "a" {
			return os.ErrDeadlineExceeded
		}
		return nil
	}}
	rep := r.runAll([]Entry{{ID: "a"}, {ID: "b"}})
	if len(rep.Done) != 0 || rep.Failed != "a" {
		t.Fatalf("a failed entry ends the run, as make lab does: %+v", rep)
	}
}

func TestTheChildEnvironmentCarriesTheLockAndNoSecretVariable(t *testing.T) {
	t.Setenv("PORT49_LAB_TOKEN_DUMP", "x")
	env := childEnv(Entry{Platforms: "eos", Env: map[string]string{"PORT49_LAB_REMEASURE": "L10"}}, 3)
	joined := strings.Join(env, "\n")
	for _, want := range []string{"PORT49_LAB_LOCK_FD=3", "PORT49_LAB_PLATFORMS=eos", "PORT49_LAB_REMEASURE=L10"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("child env lacks %s", want)
		}
	}
	if strings.Contains(joined, "TOKEN_DUMP") {
		t.Fatal("a variable naming a token reached the child")
	}
}

// A guard entry belongs to a row by its leading L<N>: L26b names L26, and L53
// does not name L5.
func TestLoadManifestMatchesGuardNamesToRowsByTheirLeadingID(t *testing.T) {
	load := func(rows, names string) error {
		p := filepath.Join(t.TempDir(), "m.yaml")
		y := "entries:\n  - {id: x, run: '^TestX$', rows: [" + rows + "], env: {PORT49_LAB_REMEASURE: \"" + names + "\"}}\n"
		os.WriteFile(p, []byte(y), 0o600)
		_, err := loadManifest(p, specPath)
		return err
	}
	if err := load("L26", "L26b,L26c"); err != nil {
		t.Fatalf("L26b names L26: %v", err)
	}
	if err := load("L5", "L53"); err == nil {
		t.Fatal("L53 must not satisfy closed row L5")
	}
}
