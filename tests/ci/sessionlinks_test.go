package ci

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// This repository is going public: no Claude Code session link or session trailer may sit in a
// tracked file (CLAUDE.md). .gitleaks.toml's claude-session-link rule is the one definition; these
// tests read its regex from there, so the scan, CI and the tree agree.

// sessionLinkRule is the claude-session-link rule's regex, taken from .gitleaks.toml by a line scan.
func sessionLinkRule(t *testing.T) *regexp.Regexp {
	t.Helper()
	f, err := os.Open("../../.gitleaks.toml")
	if err != nil {
		t.Fatal(err)
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
			return regexp.MustCompile(strings.TrimSuffix(strings.TrimPrefix(l, "regex = '''"), "'''"))
		case in && strings.HasPrefix(l, "[[rules]]"):
			t.Fatal("the claude-session-link rule has no regex")
		}
	}
	t.Fatal(".gitleaks.toml has no claude-session-link rule")
	return nil
}

func TestTheSessionLinkRuleCatchesALink(t *testing.T) {
	rx := sessionLinkRule(t)
	// Assembled here, so that no committed file matches.
	for _, s := range []string{
		"https://claude" + ".ai/code/session_" + strings.Repeat("A", 24),
		"Claude-" + "Session: https://example.invalid/x",
		"Claude-" + "Session:https://example.invalid/x",
	} {
		if !rx.MatchString(s) {
			t.Errorf("the rule misses %q", s)
		}
	}
	prose := "no `Claude-" + "Session:` line and no claude.ai session link"
	if rx.MatchString(prose) {
		t.Errorf("the rule matches the prose that forbids a link: %q", prose)
	}
}

func TestNoSessionLinkInTheTree(t *testing.T) {
	rx := sessionLinkRule(t)
	cmd := exec.Command("git", "ls-files", "-z")
	cmd.Dir = "../.."
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	never := []string{"realm.json", "*.env", "*-key.pem", "*.keytab"}
	for _, name := range strings.Split(string(out), "\x00") {
		if name == "" {
			continue
		}
		skip := false
		for _, p := range never {
			if ok, _ := filepath.Match(p, filepath.Base(name)); ok {
				skip = true
			}
		}
		if skip {
			continue
		}
		b, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			continue // a tracked file removed in the working tree
		}
		if bytes.IndexByte(b, 0) >= 0 {
			continue // binary: a capture, not text
		}
		if loc := rx.FindIndex(b); loc != nil {
			t.Errorf("%s:%d holds a session link or trailer", name, bytes.Count(b[:loc[0]], []byte("\n"))+1)
		}
	}
}
