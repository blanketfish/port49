package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const wiringNote = "## Observation\n\n| cell | outcome | elapsed |\n|---|---|---|\n| a | PASS | 1s |\n| b | PASS | 2s |\n"

// gitRepo makes a repository in a temp directory, commits the notes, and makes it the working directory.
func gitRepo(t *testing.T, files map[string]string) {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("add", "-A")
	run("commit", "-q", "-m", "notes")
	t.Chdir(dir)
}

// afterRun is the entry closure's tail: a rewritten note whose verdict changed fails the entry (the mutation
// that turns checkVerdicts into nil must fail this test), and a note that did not change passes.
func TestAfterRunFailsAnEntryWhoseVerdictChanged(t *testing.T) {
	gitRepo(t, map[string]string{"results/L1-x.md": wiringNote})
	e := Entry{ID: "L1", Notes: []string{"results/L1-x.md"}}
	start := time.Now().Add(-time.Minute)

	if err := afterRun(e, start, "true"); err != nil {
		t.Fatalf("an unchanged note passes: %v", err)
	}
	if err := os.WriteFile("results/L1-x.md", []byte(strings.Replace(wiringNote, "| b | PASS |", "| b | FAIL |", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	err := afterRun(e, start, "true")
	if err == nil || !strings.Contains(err.Error(), "PASS | <d> -> FAIL | <d>") || !strings.Contains(err.Error(), "L1") {
		t.Fatalf("a flipped row must fail the entry, naming it and old -> new: %v", err)
	}
}

// The entry closure in run() must end in afterRun: a closure that stops at notesRewritten (or at diffNotes)
// leaves the verdict check unwired while afterRun's own test stays green.
func TestRunsEntryClosureEndsInAfterRun(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	i := strings.Index(src, "func run() int {")
	if i < 0 {
		t.Fatal("run() moved")
	}
	body := src[i:]
	if j := strings.Index(body, "\n}\n"); j >= 0 {
		body = body[:j]
	}
	if !strings.Contains(body, "return afterRun(e, start, notediff)") {
		t.Error("run()'s entry closure does not end in `return afterRun(e, start, notediff)`")
	}
	for _, bypass := range []string{"notesRewritten(", "diffNotes(", "checkVerdicts("} {
		if strings.Contains(body, bypass) {
			t.Errorf("run() calls %s itself: the judging steps belong in afterRun", bypass)
		}
	}
}

func TestCheckVerdictsRefusesANoteHEADDoesNotHave(t *testing.T) {
	gitRepo(t, map[string]string{"results/L1-x.md": wiringNote})
	if err := os.WriteFile("results/L2-new.md", []byte(wiringNote), 0o644); err != nil {
		t.Fatal(err)
	}
	err := checkVerdicts(Entry{ID: "L2", Notes: []string{"results/L2-new.md"}})
	if err == nil || !strings.Contains(err.Error(), "HEAD") {
		t.Fatalf("a manifest note belongs to a closed row, so a missing HEAD copy is an error: %v", err)
	}
}

func TestCheckVerdictsRefusesWhenGitCannotRun(t *testing.T) {
	// Outside any repository, and with git off the PATH: neither is a silent pass.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "n.md"), []byte(wiringNote), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv("GIT_CEILING_DIRECTORIES", filepath.Dir(dir))
	if err := checkVerdicts(Entry{ID: "L1", Notes: []string{"n.md"}}); err == nil {
		t.Fatal("outside a repository is an error")
	}
	t.Setenv("PATH", "")
	if err := checkVerdicts(Entry{ID: "L1", Notes: []string{"n.md"}}); err == nil {
		t.Fatal("git missing from PATH is an error")
	}
}

func TestCheckVerdictsRefusesANoteThatParsesNoRows(t *testing.T) {
	gitRepo(t, map[string]string{"results/L1-x.md": "# L1\n\nprose only\n"})
	e := Entry{ID: "L1", Notes: []string{"results/L1-x.md"}}
	if err := checkVerdicts(e); err == nil || !strings.Contains(err.Error(), "no verdict rows") {
		t.Fatalf("a note with no verdict rows must fail loudly: %v", err)
	}
	e.Verdicts = "none"
	if err := checkVerdicts(e); err != nil {
		t.Fatalf("`verdicts: none` marks it observation-only: %v", err)
	}
	e = Entry{ID: "L1", Notes: []string{"results/L1-x.md"}, NoVerdictNotes: []string{"results/L1-x.md"}}
	if err := checkVerdicts(e); err != nil {
		t.Fatalf("no_verdict_notes marks one note: %v", err)
	}
}
