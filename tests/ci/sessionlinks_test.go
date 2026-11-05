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
	_, raw := load(t, "../../.github/workflows/leaks.yml")
	for _, want := range []string{"github.event.before", "github.event.pull_request.body", "edited"} {
		if !strings.Contains(raw, want) {
			t.Errorf("leaks.yml does not mention %s: the push, the PR body and an edited PR are checked too", want)
		}
	}
}

func TestARangeWithAnEmptySideIsRefused(t *testing.T) {
	rx := sessionLinkRule(t)
	repo := t.TempDir()
	gitIn(t, repo, "init", "-q")
	gitIn(t, repo, "commit", "-q", "--allow-empty", "-m", "base")
	for _, rev := range []string{"..HEAD", "HEAD..", "..", "HEAD", ""} {
		if _, err := sessionlink.CheckLog(repo, rev, rx); err == nil {
			t.Errorf("the range %q was accepted", rev)
		}
	}
}

// git drops # lines and everything from the scissors line (commit -v appends the diff) before it
// stores a message; the hook's file is judged the same way.
func TestTheHookJudgesAMessageAsGitStoresIt(t *testing.T) {
	rx := sessionLinkRule(t)
	trailer := "Claude-" + "Session: https://claude" + ".ai/code/session_" + strings.Repeat("A", 24)
	f := filepath.Join(t.TempDir(), "MSG")
	for name, c := range map[string]struct {
		msg  string
		want bool
	}{
		"comment":  {"fix: x\n\n# " + trailer + "\n", false},
		"scissors": {"fix: x\n\n# ------------------------ >8 ------------------------\n# Do not modify or remove the line above.\n+" + trailer + "\n", false},
		"real":     {"fix: x\n\n" + trailer + "\n# a comment\n", true},
		"below":    {"fix: x\n\n# ------------------------ >8 ------------------------\n", false},
	} {
		if err := os.WriteFile(f, []byte(c.msg), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, _ := sessionlink.CheckFile(f, rx); got != c.want {
			t.Errorf("%s: CheckFile = %v, want %v", name, got, c.want)
		}
	}
}

func TestAPullRequestBodyIsChecked(t *testing.T) {
	rx := sessionLinkRule(t)
	trailer := "https://claude" + ".ai/code/session_" + strings.Repeat("B", 24)
	if !sessionlink.CheckText("## Summary\n\nGenerated\n\n"+trailer, rx) {
		t.Error("a PR body carrying a session link passed")
	}
	if sessionlink.CheckText("## Summary\n\nNo link here, and a # heading is not a comment.", rx) {
		t.Error("a clean PR body failed")
	}
}

func TestAPushRangeOfAllZerosChecksTheNewCommitAlone(t *testing.T) {
	rx := sessionLinkRule(t)
	repo := t.TempDir()
	gitIn(t, repo, "init", "-q")
	gitIn(t, repo, "commit", "-q", "--allow-empty", "-m", "base "+"Claude-"+"Session: https://example.invalid/old")
	gitIn(t, repo, "commit", "-q", "--allow-empty", "-m", "feat: new")
	after := gitIn(t, repo, "rev-parse", "HEAD")
	rev := sessionlink.PushRev(strings.Repeat("0", 40), after)
	if bad, err := sessionlink.CheckLog(repo, rev, rx); err != nil || len(bad) != 0 {
		t.Errorf("the new commit alone: %v %v (rev %q)", bad, err, rev)
	}
	trailer := "Claude-" + "Session: https://example.invalid/x"
	gitIn(t, repo, "commit", "-q", "--allow-empty", "-m", "feat: leaky "+trailer)
	after2 := gitIn(t, repo, "rev-parse", "HEAD")
	if bad, _ := sessionlink.CheckLog(repo, sessionlink.PushRev(after, after2), rx); len(bad) != 1 {
		t.Errorf("a pushed range with a trailer: %v", bad)
	}
}
