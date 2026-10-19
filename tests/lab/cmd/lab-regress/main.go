// Command lab-regress reruns the closed lab entries in tests/lab/regress.yaml on
// the lab host, under one held lab lock, and diffs each rewritten results note
// against HEAD (plan 11b; spec §13 decision 52 ruling 7).
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	lockPath     = "/tmp/port49-lab.lock"
	stopPath     = "/tmp/port49-STOP-LAB"
	repoSpecPath = "docs/design/2026-08-23-policy-engine-spec.md"
)

type report struct {
	Done            []string
	Skipped         []string
	Minutes         map[string]float64
	Stopped, Failed string
}

// failed is whether the run as a whole failed: an entry failed, the operator
// stopped it, or an entry measured nothing because its test skipped (unless
// the operator opted out with -allow-skip).
func (r report) failed(allowSkip bool) bool {
	return r.Failed != "" || r.Stopped != "" || (len(r.Skipped) > 0 && !allowSkip)
}

// skippedError is a run whose top-level test skipped: the binary exited 0 and
// measured nothing, so the entry is not done and its notes are not diffed.
type skippedError struct{ Tests []string }

func (e *skippedError) Error() string {
	return "skipped, so nothing was measured: " + strings.Join(e.Tests, ", ")
}

// skipScanner copies nothing and keeps the names of the top-level tests that
// the -test.v output shows skipped: a "--- SKIP: Name" at column 0. A subtest's
// line is indented, and a platform the test does not run is a subtest skip.
type skipScanner struct {
	buf     bytes.Buffer
	skipped []string
}

func (s *skipScanner) Write(p []byte) (int, error) {
	s.buf.Write(p)
	for {
		i := bytes.IndexByte(s.buf.Bytes(), '\n')
		if i < 0 {
			return len(p), nil
		}
		s.line(string(s.buf.Next(i + 1)))
	}
}

func (s *skipScanner) line(ln string) {
	if rest, ok := strings.CutPrefix(ln, "--- SKIP: "); ok {
		s.skipped = append(s.skipped, strings.Fields(rest)[0])
	}
}

// Close takes a last line that has no newline.
func (s *skipScanner) Close() {
	if s.buf.Len() > 0 {
		s.line(s.buf.String())
		s.buf.Reset()
	}
}

func (s *skipScanner) Skipped() []string { return s.skipped }

// timeoutFor is the entry's budget: its timeout_minutes, else make lab's 120
// minutes a platform (an entry naming no platform is one run).
func timeoutFor(e Entry) time.Duration {
	if e.TimeoutMinutes > 0 {
		return time.Duration(e.TimeoutMinutes) * time.Minute
	}
	n := 1
	if e.Platforms != "" {
		n = len(strings.Split(e.Platforms, ","))
	}
	return time.Duration(n) * 120 * time.Minute
}

// deadlines are the binary's -test.timeout and the runner's own, later one.
// The binary's fires first, and the runner then waits for it to finish before
// it signals, so a run that overruns is stopped by the test's own timeout
// handling and not by a kill in the middle of a deploy.
func deadlines(e Entry) (binary, runner time.Duration) {
	binary = timeoutFor(e)
	return binary, binary + 15*time.Minute
}

type runner struct {
	stopPath string
	exec     func(Entry) error
}

func (r *runner) runAll(entries []Entry) report {
	rep := report{Minutes: map[string]float64{}}
	for _, e := range entries {
		if _, err := os.Stat(r.stopPath); err == nil {
			rep.Stopped = e.ID
			return rep
		}
		start := time.Now()
		if err := r.exec(e); err != nil {
			var sk *skippedError
			if errors.As(err, &sk) {
				fmt.Fprintf(os.Stderr, "lab-regress: %s SKIPPED: %v\n", e.ID, sk)
				rep.Skipped = append(rep.Skipped, e.ID)
				continue
			}
			rep.Failed = e.ID
			return rep
		}
		rep.Done = append(rep.Done, e.ID)
		rep.Minutes[e.ID] = time.Since(start).Minutes()
	}
	return rep
}

// childEnv is the caller's environment, less any variable whose name holds
// TOKEN, SECRET or PASSWORD (L27_TOKEN among them: no manifest entry needs one,
// and an entry that did would name it in env) and of the operator's own
// PORT49_LAB_PLATFORMS and PORT49_LAB_REMEASURE (an entry that names none must
// not run on, or re-measure, what the shell happened to export), plus the held
// lock's descriptor and the entry's own settings.
func childEnv(e Entry, lockFD int) []string {
	var env []string
	for _, kv := range os.Environ() {
		name := strings.ToUpper(strings.SplitN(kv, "=", 2)[0])
		if strings.Contains(name, "TOKEN") || strings.Contains(name, "SECRET") || strings.Contains(name, "PASSWORD") {
			continue
		}
		if name == "PORT49_LAB_PLATFORMS" || name == "PORT49_LAB_REMEASURE" {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, fmt.Sprintf("PORT49_LAB_LOCK_FD=%d", lockFD))
	if e.Platforms != "" {
		env = append(env, "PORT49_LAB_PLATFORMS="+e.Platforms)
	}
	for k, v := range e.Env {
		env = append(env, k+"="+v)
	}
	return env
}

func main() { os.Exit(run()) }

// run is main with an exit code, so every path, a failed entry and the stop
// sentinel included, runs its defers: the test binary never stays in /tmp.
func run() int {
	manifest := flag.String("manifest", "tests/lab/regress.yaml", "the closed-entry manifest")
	only := flag.String("only", "", "comma-separated entry ids; empty runs all")
	dry := flag.Bool("dry-run", false, "list the entries and their last measured minutes; run nothing")
	allowSkip := flag.Bool("allow-skip", false, "do not fail the run for an entry whose test skipped")
	flag.Parse()
	entries, err := loadManifest(*manifest, repoSpecPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	entries = pick(entries, *only)
	if *dry {
		total := 0
		for _, e := range entries {
			fmt.Printf("%-16s %-28s %4d min  %s\n", e.ID, e.Platforms, e.MeasuredMinutes, e.Run)
			total += e.MeasuredMinutes
		}
		fmt.Printf("total %d min (last measured)\n", total)
		return 0
	}
	lock, err := holdLock(lockPath, "lab-regress pid "+fmt.Sprint(os.Getpid()))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer lock.Close()
	dir, err := os.MkdirTemp("", "port49-lab-regress-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)
	bin := filepath.Join(dir, "lab.test")
	if out, err := exec.Command("go", "test", "-c", "-tags", "lab", "-o", bin, "./tests/lab/").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building the lab test binary: %v\n%s", err, out)
		return 1
	}
	// notediff is built once, not by a go run per note.
	notediff := filepath.Join(dir, "notediff")
	if out, err := exec.Command("go", "build", "-o", notediff, "./tests/lab/cmd/notediff").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building notediff: %v\n%s", err, out)
		return 1
	}
	r := &runner{stopPath: stopPath, exec: func(e Entry) error {
		fmt.Printf("=== lab-regress %s ===\n", e.ID)
		testTimeout, killAfter := deadlines(e)
		ctx, cancel := context.WithTimeout(context.Background(), killAfter)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, "-test.run", e.Run, "-test.count=1", "-test.v",
			"-test.timeout", testTimeout.String())
		cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) } // the harness's own teardown
		cmd.WaitDelay = 10 * time.Minute
		cmd.Dir = "tests/lab" // as go test runs a package's binary
		cmd.Env = childEnv(e, 3)
		cmd.ExtraFiles = []*os.File{lock} // fd 3, straight into the test binary
		scan := &skipScanner{}
		cmd.Stdout, cmd.Stderr = io.MultiWriter(os.Stdout, scan), os.Stderr
		err := cmd.Run()
		scan.Close()
		if err != nil {
			return err
		}
		if sk := scan.Skipped(); len(sk) > 0 {
			return &skippedError{Tests: sk}
		}
		return diffNotes(notediff, e.Notes)
	}}
	rep := r.runAll(entries)
	printReport(rep)
	if rep.failed(*allowSkip) {
		return 1
	}
	return 0
}

func pick(all []Entry, only string) []Entry {
	if only == "" {
		return all
	}
	want := map[string]bool{}
	for _, id := range strings.Split(only, ",") {
		want[strings.TrimSpace(id)] = true
	}
	var out []Entry
	for _, e := range all {
		if want[e.ID] {
			out = append(out, e)
		}
	}
	return out
}

// diffNotes reports each rewritten note's changed observations (Task 3). It
// reports and never fails on a difference: the lab is the truth, and a change
// is for a person to read (CLAUDE.md, lab register rule 4).
func diffNotes(notediff string, notes []string) error {
	for _, n := range notes {
		cmd := exec.Command(notediff, "-note", n)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("notediff %s: %w", n, err)
		}
	}
	return nil
}

func printReport(rep report) {
	total := 0.0
	for _, id := range rep.Done {
		fmt.Printf("lab-regress: %-16s %6.1f min\n", id, rep.Minutes[id])
		total += rep.Minutes[id]
	}
	fmt.Printf("lab-regress: %d entries done in %.1f min", len(rep.Done), total)
	if len(rep.Skipped) > 0 {
		fmt.Printf("; SKIPPED, nothing measured: %s", strings.Join(rep.Skipped, ", "))
	}
	if rep.Stopped != "" {
		fmt.Printf("; stopped by %s before %s", stopPath, rep.Stopped)
	}
	if rep.Failed != "" {
		fmt.Printf("; %s FAILED, the entries after it were not run", rep.Failed)
	}
	fmt.Println()
}
