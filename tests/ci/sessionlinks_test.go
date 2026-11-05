package ci

import (
	"bytes"
	"github.com/blanketfish/port49/tests/ci/sessionlink"
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

// sessionLinkRule is the claude-session-link rule's regex from .gitleaks.toml.
func sessionLinkRule(t *testing.T) *regexp.Regexp {
	t.Helper()
	rx, err := sessionlink.Rule("../../.gitleaks.toml")
	if err != nil {
		t.Fatal(err)
	}
	return rx
}

func TestTheSessionLinkRuleCatchesALink(t *testing.T) {
	rx := sessionLinkRule(t)
	// Assembled here, so that no committed file matches.
	for _, s := range []string{
		"https://claude" + ".ai/code/session_" + strings.Repeat("A", 24),
		"Claude-" + "Session: https://example.invalid/x",
		"Claude-" + "Session:https://example.invalid/x",
		"CLAUDE" + ".AI/CODE/SESSION_" + strings.Repeat("a", 24),
		"claude-" + "session: https://example.invalid/x",
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
	for name, b := range trackedText(t) {
		if loc := rx.FindIndex(b); loc != nil {
			t.Errorf("%s:%d holds a session link or trailer", name, bytes.Count(b[:loc[0]], []byte("\n"))+1)
		}
	}
}

// trackedText is every tracked text file by name, skipping the files that are never read (realm.json,
// *.env, *-key.pem, *.keytab), binary files, and tracked files absent from the working tree; any other read error fails.
func trackedText(t *testing.T) map[string][]byte {
	t.Helper()
	cmd := exec.Command("git", "ls-files", "-z")
	cmd.Dir = "../.."
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	never := []string{"realm.json", "*.env", "*-key.pem", "*.keytab"}
	files := map[string][]byte{}
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
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatalf("reading tracked file %s: %v", name, err)
		}
		if bytes.IndexByte(b, 0) >= 0 {
			continue
		}
		files[name] = b
	}
	return files
}

func gitIn(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

// gitleaks reads a commit's patch, never its message, so a trailer there is caught here.
func TestACommitMessageWithASessionTrailerFails(t *testing.T) {
	rx, err := sessionlink.Rule("../../.gitleaks.toml")
	if err != nil {
		t.Fatal(err)
	}
	repo := t.TempDir()
	gitIn(t, repo, "init", "-q")
	gitIn(t, repo, "commit", "-q", "--allow-empty", "-m", "base")
	base := gitIn(t, repo, "rev-parse", "HEAD")
	gitIn(t, repo, "commit", "-q", "--allow-empty", "-m", "feat: clean\n\nCo-Authored-By: Claude <noreply@anthropic.com>")
	clean, err := sessionlink.CheckLog(repo, base+"..HEAD", rx)
	if err != nil || len(clean) != 0 {
		t.Fatalf("a clean message failed: %v %v", clean, err)
	}
	trailer := "Claude-" + "Session: https://claude" + ".ai/code/session_" + strings.Repeat("A", 24)
	gitIn(t, repo, "commit", "-q", "--allow-empty", "-m", "feat: leaky\n\n"+trailer)
	bad, err := sessionlink.CheckLog(repo, base+"..HEAD", rx)
	if err != nil || len(bad) != 1 {
		t.Fatalf("the trailer was not caught: %v %v", bad, err)
	}
	// The hook's file form, and an upper-case spelling.
	f := filepath.Join(t.TempDir(), "MSG")
	for msg, want := range map[string]bool{
		"fix: x\n\n" + trailer + "\n":                            true,
		strings.ToUpper(trailer):                                 true,
		"fix: x\n\nno `Claude-" + "Session:` line and no link\n": false,
	} {
		if err := os.WriteFile(f, []byte(msg), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, _ := sessionlink.CheckFile(f, rx); got != want {
			t.Errorf("CheckFile = %v, want %v", got, want)
		}
	}
}

// The check runs where a commit can be made or proposed: the pull request's own commits in CI, and a
// commit-msg hook beside the pre-commit one.
func TestTheMessageCheckIsWiredIn(t *testing.T) {
	hook := readRepo(t, ".githooks", "commit-msg")
	if !strings.Contains(hook, "tests/ci/cmd/sessionmsg") {
		t.Error(".githooks/commit-msg does not run the sessionmsg check")
	}
	if fi, err := os.Stat("../../.githooks/commit-msg"); err != nil || fi.Mode()&0o111 == 0 {
		t.Error(".githooks/commit-msg is not executable")
	}
	f, _ := load(t, "../../.github/workflows/leaks.yml")
	found := false
	for _, j := range f.Jobs {
		for _, s := range j.Steps {
			if strings.Contains(s.Run, "tests/ci/cmd/sessionmsg") && strings.Contains(s.If, "pull_request") {
				found = true
			}
		}
	}
	if !found {
		t.Error("leaks.yml has no pull_request step running sessionmsg")
	}
}
