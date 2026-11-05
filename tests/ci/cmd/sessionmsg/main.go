// Command sessionmsg fails when a commit message carries a Claude Code session link or trailer
// (the claude-session-link rule in .gitleaks.toml, which gitleaks cannot apply to messages).
//
//	sessionmsg FILE            a commit-msg hook's message file
//	sessionmsg -range A..B     the commits of a pull request, in CI
//	sessionmsg -before B -after A   a push: B..A, or A alone when B is all zeros (a new branch)
//	sessionmsg -env NAME       free text in an environment variable (a pull request's body)
//
// It prints commit names or a file name, never the matched text. Old history keeps its trailers
// (no rewrite, Ryan 2026-10-15), so CI checks only the pull request's own range.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/blanketfish/port49/tests/ci/sessionlink"
)

func main() {
	toml := flag.String("toml", ".gitleaks.toml", "the gitleaks config holding the claude-session-link rule")
	rng := flag.String("range", "", "a git revision range whose commit messages are checked")
	before := flag.String("before", "", "a push's previous tip (with -after)")
	after := flag.String("after", "", "a push's new tip (with -before)")
	var envs []string
	flag.Func("env", "an environment variable whose text is checked (repeatable)", func(v string) error {
		envs = append(envs, v)
		return nil
	})
	flag.Parse()
	rx, err := sessionlink.Rule(*toml)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sessionmsg:", err)
		os.Exit(2)
	}
	fail := false
	if *before != "" && *after == "" {
		fmt.Fprintln(os.Stderr, "sessionmsg: -before without -after")
		os.Exit(2)
	}
	if *after != "" {
		*rng = sessionlink.PushRev(*before, *after)
	}
	if *rng == "" && len(envs) == 0 && flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "sessionmsg: nothing to check: give a message file, -range, -before/-after or -env")
		os.Exit(2)
	}
	for _, name := range envs {
		if sessionlink.CheckText(os.Getenv(name), rx) {
			fmt.Fprintf(os.Stderr, "sessionmsg: %s carries a Claude session link or trailer; remove it\n", name)
			fail = true
		}
	}
	if *rng != "" {
		bad, err := sessionlink.CheckLog(".", *rng, rx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sessionmsg:", err)
			os.Exit(2)
		}
		for _, sha := range bad {
			fmt.Fprintf(os.Stderr, "sessionmsg: commit %s carries a Claude session link or trailer; reword it\n", sha)
			fail = true
		}
	}
	for _, f := range flag.Args() {
		hit, err := sessionlink.CheckFile(f, rx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "sessionmsg:", err)
			os.Exit(2)
		}
		if hit {
			fmt.Fprintf(os.Stderr, "sessionmsg: the commit message carries a Claude session link or trailer; remove it (CLAUDE.md)\n")
			fail = true
		}
	}
	if fail {
		os.Exit(1)
	}
}
