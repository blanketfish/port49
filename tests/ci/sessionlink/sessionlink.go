// Package sessionlink is the claude-session-link rule from .gitleaks.toml, applied to what
// gitleaks does not read: commit messages. gitleaks scans a commit's patch, never its message.
package sessionlink

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Rule is the claude-session-link rule's regex, taken from the TOML file by a line scan: the one
// definition the scan, CI, the hook and the tree test all share.
func Rule(tomlPath string) (*regexp.Regexp, error) {
	f, err := os.Open(tomlPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	in := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		switch {
		case l == `id = "claude-session-link"`:
			in = true
		case in && strings.HasPrefix(l, "regex = '''") && strings.HasSuffix(l, "'''"):
			return regexp.Compile(strings.TrimSuffix(strings.TrimPrefix(l, "regex = '''"), "'''"))
		case in && strings.HasPrefix(l, "[[rules]]"):
			return nil, fmt.Errorf("the claude-session-link rule in %s has no regex", tomlPath)
		}
	}
	return nil, fmt.Errorf("%s has no claude-session-link rule", tomlPath)
}

// CheckLog returns the abbreviated SHAs of the commits in rev (a range such as base..head) whose
// message matches rx, run in dir. It names commits, never the matched text.
func CheckLog(dir, rev string, rx *regexp.Regexp) ([]string, error) {
	if err := checkRev(rev); err != nil {
		return nil, err
	}
	cmd := exec.Command("git", "log", "-z", "--format=%h%n%B", rev)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git log %s: %w", rev, err)
	}
	var bad []string
	for _, rec := range strings.Split(string(out), "\x00") {
		sha, msg, _ := strings.Cut(strings.TrimLeft(rec, "\n"), "\n")
		if sha != "" && rx.MatchString(msg) {
			bad = append(bad, sha)
		}
	}
	return bad, nil
}

// checkRev refuses a revision that is not a range with both sides present (A..B), or a single
// commit alone (C^!): an empty side would turn a misconfigured variable into a silent pass.
func checkRev(rev string) error {
	if strings.HasSuffix(rev, "^!") && len(rev) > 2 && !strings.Contains(rev, "..") {
		return nil
	}
	a, b, ok := strings.Cut(rev, "..")
	if !ok || a == "" || b == "" || strings.HasPrefix(b, ".") {
		return fmt.Errorf("the revision %q is not a range with both sides (A..B) or a single commit (C^!)", rev)
	}
	return nil
}

// PushRev is the revision to check for a push event: before..after, or after alone when the branch is
// new (before is all zeros or empty).
func PushRev(before, after string) string {
	if strings.Trim(before, "0") == "" {
		return after + "^!"
	}
	return before + ".." + after
}

// CheckText reports whether free text, such as a pull request body or title, matches rx.
func CheckText(text string, rx *regexp.Regexp) bool { return rx.MatchString(text) }

// stored is a commit-msg file as git will store it: lines starting with # dropped, and everything
// from the scissors line (which commit -v follows with the diff) cut.
func stored(msg string) string {
	var out []string
	for _, l := range strings.Split(msg, "\n") {
		if strings.HasPrefix(l, "# ------------------------ >8 ------------------------") {
			break
		}
		if strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// CheckFile reports whether the message file (a commit-msg hook's argument), as git will store it,
// matches rx.
func CheckFile(path string, rx *regexp.Regexp) (bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	return rx.MatchString(stored(string(b))), nil
}
