// Command lab-regress reruns the closed lab entries in tests/lab/regress.yaml on
// the lab host, under one held lab lock, and diffs each rewritten results note
// against HEAD (plan 11b; spec §13 decision 52 ruling 7).
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	lockPath     = "/tmp/port49-lab.lock"
	stopPath     = "/tmp/port49-STOP-LAB"
	repoSpecPath = "docs/design/2026-08-23-policy-engine-spec.md"
)

type report struct {
	Done            []string
	Minutes         map[string]float64
	Stopped, Failed string
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
// and an entry that did would name it in env), plus the held lock's
// descriptor and the entry's own settings.
func childEnv(e Entry, lockFD int) []string {
	var env []string
	for _, kv := range os.Environ() {
		name := strings.ToUpper(strings.SplitN(kv, "=", 2)[0])
		if strings.Contains(name, "TOKEN") || strings.Contains(name, "SECRET") || strings.Contains(name, "PASSWORD") {
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

func main() {
	manifest := flag.String("manifest", "tests/lab/regress.yaml", "the closed-entry manifest")
	only := flag.String("only", "", "comma-separated entry ids; empty runs all")
	dry := flag.Bool("dry-run", false, "list the entries and their last measured minutes; run nothing")
	flag.Parse()
	entries, err := loadManifest(*manifest, repoSpecPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	entries = pick(entries, *only)
	if *dry {
		total := 0
		for _, e := range entries {
			fmt.Printf("%-16s %-28s %4d min  %s\n", e.ID, e.Platforms, e.MeasuredMinutes, e.Run)
			total += e.MeasuredMinutes
		}
		fmt.Printf("total %d min (last measured)\n", total)
		return
	}
	lock, err := holdLock(lockPath, "lab-regress pid "+fmt.Sprint(os.Getpid()))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	bin := filepath.Join(os.TempDir(), fmt.Sprintf("port49-lab-regress-%d.test", os.Getpid()))
	defer os.Remove(bin)
	if out, err := exec.Command("go", "test", "-c", "-tags", "lab", "-o", bin, "./tests/lab/").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building the lab test binary: %v\n%s", err, out)
		os.Exit(1)
	}
	r := &runner{stopPath: stopPath, exec: func(e Entry) error {
		fmt.Printf("=== lab-regress %s ===\n", e.ID)
		cmd := exec.Command(bin, "-test.run", e.Run, "-test.count=1", "-test.v", "-test.timeout", "300m")
		cmd.Dir = "tests/lab" // as go test runs a package's binary
		cmd.Env = childEnv(e, 3)
		cmd.ExtraFiles = []*os.File{lock} // fd 3, straight into the test binary
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
		return diffNotes(e.Notes)
	}}
	rep := r.runAll(entries)
	printReport(rep)
	if rep.Failed != "" || rep.Stopped != "" {
		os.Exit(1)
	}
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
// reports and never fails: the lab is the truth, and a change is for a person
// to read (CLAUDE.md, lab register rule 4).
func diffNotes(notes []string) error {
	for _, n := range notes {
		cmd := exec.Command("go", "run", "./tests/lab/cmd/notediff", "-note", n)
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
	if rep.Stopped != "" {
		fmt.Printf("; stopped by %s before %s", stopPath, rep.Stopped)
	}
	if rep.Failed != "" {
		fmt.Printf("; %s FAILED, the entries after it were not run", rep.Failed)
	}
	fmt.Println()
}
