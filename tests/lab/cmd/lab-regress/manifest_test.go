package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
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

func writeManifest(t *testing.T, y string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "m.yaml")
	if err := os.WriteFile(p, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadManifestRefusesADuplicateIDAndAnEmptyRun(t *testing.T) {
	p := writeManifest(t, "entries:\n  - {id: a, run: '^TestA$'}\n  - {id: a, run: '^TestB$'}\n")
	if _, err := loadManifest(p, specPath); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("a duplicate id makes -only run both entries: %v", err)
	}
	p = writeManifest(t, "entries:\n  - {id: a}\n")
	if _, err := loadManifest(p, specPath); err == nil || !strings.Contains(err.Error(), "run") {
		t.Fatalf("an entry with no run pattern must be refused: %v", err)
	}
}

func TestLoadManifestRefusesAnExclusionWithoutAReason(t *testing.T) {
	p := writeManifest(t, "entries: []\nexcluded:\n  - {rows: [L62]}\n")
	if _, err := loadManifest(p, specPath); err == nil || !strings.Contains(err.Error(), "reason") {
		t.Fatalf("an exclusion records why: %v", err)
	}
}

// The runner reruns closed entries (spec decision 52 ruling 7): every closed
// row of §15 is in an entry's rows or excluded with a reason, so a row that
// drops out of the regression is a recorded decision and never an oversight.
func TestEveryClosedRowIsRunOrExcluded(t *testing.T) {
	m, err := loadManifestFile("../../regress.yaml", specPath)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatal(err)
	}
	covered := map[string]string{}
	for _, e := range m.Entries {
		for _, r := range e.Rows {
			covered[r] = "entry " + e.ID
		}
	}
	for _, x := range m.Excluded {
		for _, r := range x.Rows {
			if covered[r] == "" {
				covered[r] = "excluded"
			}
		}
	}
	for _, row := range closedRows(string(spec)) {
		if covered[row] == "" {
			t.Errorf("%s is closed in spec §15 and is neither in an entry's rows nor in excluded", row)
		}
	}
}

func TestEntryTimeouts(t *testing.T) {
	if got := timeoutFor(Entry{TimeoutMinutes: 180}); got != 180*time.Minute {
		t.Fatalf("an entry's own timeout_minutes wins: %v", got)
	}
	if got := timeoutFor(Entry{Platforms: "eos,vsrx"}); got != 240*time.Minute {
		t.Fatalf("the default is 120 minutes a platform, as make lab budgets: %v", got)
	}
	if got := timeoutFor(Entry{}); got != 120*time.Minute {
		t.Fatalf("an entry with no platforms is one 120 minute run: %v", got)
	}
	// -test.timeout is a panic that skips TestMain's teardown; the harness's
	// SIGTERM handler is what tears down. So the runner's deadline (SIGTERM) is
	// the budget, and the binary's own timeout is only a backstop after it.
	sigterm, backstop := deadlines(Entry{TimeoutMinutes: 60})
	if sigterm != 60*time.Minute || backstop-sigterm < 10*time.Minute {
		t.Fatalf("SIGTERM at the budget, -test.timeout well after it: %v %v", sigterm, backstop)
	}
}

func TestATopLevelSkipIsFoundAndASubtestSkipIsNot(t *testing.T) {
	out := "=== RUN   TestA\n=== RUN   TestA/eos\n    --- SKIP: TestA/eos (0.00s)\n--- PASS: TestA (1.00s)\n" +
		"--- SKIP: TestB (0.00s)\n    l74_test.go:457: PORT49_LAB_ETCD_BIN names no directory\n"
	s := &skipScanner{}
	// Written in pieces that split a line, as a pipe delivers it.
	for i := 0; i < len(out); i += 7 {
		end := min(i+7, len(out))
		s.Write([]byte(out[i:end]))
	}
	s.Close()
	if got := s.Skipped(); len(got) != 1 || got[0] != "TestB" {
		t.Fatalf("want only the top-level skip TestB, got %v", got)
	}
}

func TestASkippedEntryIsReportedAndFailsTheRunUnlessOptedOut(t *testing.T) {
	var ran []string
	r := &runner{stopPath: filepath.Join(t.TempDir(), "none"), exec: func(e Entry) error {
		ran = append(ran, e.ID)
		if e.ID == "a" {
			return &skippedError{Tests: []string{"TestA"}}
		}
		return nil
	}}
	rep := r.runAll([]Entry{{ID: "a"}, {ID: "b"}})
	if len(rep.Skipped) != 1 || rep.Skipped[0] != "a" || len(rep.Done) != 1 || rep.Done[0] != "b" {
		t.Fatalf("a skipped entry is not done, and the rest still run: %+v ran %v", rep, ran)
	}
	if !rep.failed(false) {
		t.Fatal("a skipped entry must fail the run")
	}
	if rep.failed(true) {
		t.Fatal("-allow-skip opts out")
	}
}

func TestAnEntryWithoutPlatformsOrRemeasureInheritsNoneOfTheOperators(t *testing.T) {
	t.Setenv("PORT49_LAB_PLATFORMS", "vsrx")
	t.Setenv("PORT49_LAB_REMEASURE", "L99")
	joined := strings.Join(childEnv(Entry{ID: "regions"}, 3), "\n")
	if strings.Contains(joined, "PORT49_LAB_PLATFORMS") || strings.Contains(joined, "L99") {
		t.Fatalf("the operator's selection reached an entry that names none:\n%s", joined)
	}
}

// A full run rewrites each L71 note, and TestL73 then adds its addendum to
// the notes it measures: the L71 entry must run first or it would wipe them.
func TestTheL71EntryRunsBeforeEveryL73Entry(t *testing.T) {
	entries, err := loadManifest("../../regress.yaml", specPath)
	if err != nil {
		t.Fatal(err)
	}
	l71 := -1
	for i, e := range entries {
		if e.ID == "L71" {
			l71 = i
		}
	}
	if l71 < 0 {
		t.Fatal("no L71 entry")
	}
	for i, e := range entries {
		if strings.HasPrefix(e.ID, "L73-") && i < l71 {
			t.Errorf("%s comes before the L71 entry: the L71 rerun would overwrite the addendum it records", e.ID)
		}
	}
}

func TestAProcessStillHoldingStdoutIsNamedALeak(t *testing.T) {
	err := waitError(exec.ErrWaitDelay, "L10")
	if err == nil || !strings.Contains(err.Error(), "leak") || !strings.Contains(err.Error(), "stdout") {
		t.Fatalf("name the leaked process: %v", err)
	}
	if got := waitError(nil, "L10"); got != nil {
		t.Fatalf("a clean exit is not an error: %v", got)
	}
}

// measured_minutes keeps its decimals: the first full run's passing entries
// took 723.5 minutes, and a whole-minute field read 696. L79 joined the regions
// entry at 18.9 minutes (16.2 before), so the total was 726.2; L80's nxos106 qualify entry (7.4) makes it 733.6, and L90 (3.2) 736.8.
func TestMeasuredMinutesKeepTheirDecimals(t *testing.T) {
	entries, err := loadManifest("../../regress.yaml", specPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := measuredTotal(entries); got < 736.75 || got > 736.85 {
		t.Errorf("the committed manifest's measured minutes total %.2f, want 736.8", got)
	}
}

// A note the run did not rewrite compares equal to HEAD once its header is
// masked, so notediff would print "unchanged" for a measurement nobody made
// (final review I3): an entry whose note predates its start fails, naming it.
func TestNotesRewrittenRefusesANoteOlderThanTheRun(t *testing.T) {
	dir := t.TempDir()
	stale, fresh := filepath.Join(dir, "L1-a.md"), filepath.Join(dir, "L1-b.md")
	for _, p := range []string{stale, fresh} {
		if err := os.WriteFile(p, []byte("note\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	if err := os.Chtimes(stale, start.Add(-time.Hour), start.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(fresh, start.Add(time.Second), start.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := notesRewritten([]string{fresh}, start); err != nil {
		t.Fatalf("a note the run wrote: %v", err)
	}
	err := notesRewritten([]string{fresh, stale}, start)
	if err == nil || err.Error() != stale+": not rewritten by this run" {
		t.Fatalf("got %v", err)
	}
	if err := notesRewritten([]string{filepath.Join(dir, "missing.md")}, start); err == nil {
		t.Fatal("a missing note passed")
	}
}

// The manifest is one document: entries after `---` are refused, never
// dropped from the run.
func TestASecondManifestDocumentIsRefused(t *testing.T) {
	first, err := os.ReadFile("../../regress.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "regress.yaml")
	if err := os.WriteFile(p, append(first, []byte("\n---\nentries: []\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadManifestFile(p, specPath); err == nil || !strings.Contains(err.Error(), "more than one YAML document") {
		t.Fatalf("%v", err)
	}
}
