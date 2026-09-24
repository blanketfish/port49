package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitRepo is a scratch repository holding the policy fixture, committed on
// main, with a bare repository as its origin. Identity and signing are set
// in the repository, and the machine's global and system config are not
// read (a global core.hooksPath would replace the remote's hooks), so the
// test does not depend on the machine's git config.
func gitRepo(t *testing.T) (repo, remote, pol, inv string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("HOME", t.TempDir())
	repo, remote = filepath.Join(root, "policy"), filepath.Join(root, "remote.git")
	fixturePol, fixtureInv := policyFixture(t)
	for _, args := range [][]string{{"init", "--quiet", "--bare", remote}, {"init", "--quiet", "-b", "main", repo}} {
		if out, err := exec.Command("git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	pol, inv = filepath.Join(repo, "policy.yaml"), filepath.Join(repo, "inventory.yaml")
	for src, dst := range map[string]string{fixturePol: pol, fixtureInv: inv} {
		if err := os.WriteFile(dst, readFile(t, src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"config", "user.email", "ci@example.test"}, {"config", "user.name", "ci"},
		{"config", "commit.gpgsign", "false"}, {"add", "."}, {"commit", "--quiet", "-m", "policy"},
		{"remote", "add", "origin", remote}, {"push", "--quiet", "origin", "main"}} {
		if _, err := runGit(repo, args...); err != nil {
			t.Fatal(err)
		}
	}
	return repo, remote, pol, inv
}

// `grants remove --pr` opens the pull request plan 4's edit prepares (spec
// §12; owner's ruling 2026-09-24): a branch carrying the removal and nothing
// else, pushed, and the review opened against main. The operator's checkout
// is not touched, and a policy file with uncommitted edits is refused rather
// than left out of the pull request.
func TestGrantsRemoveOpensThePullRequest(t *testing.T) {
	repo, remote, pol, inv := gitRepo(t)
	before := readFile(t, pol)
	var asked []string
	orig := openPR
	openPR = func(dir, branch, base, title, body string) (string, error) {
		asked = []string{branch, base, title, body}
		return "https://example.test/policy/pull/7", nil
	}
	t.Cleanup(func() { openPR = orig })
	var out, errb bytes.Buffer
	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "ops", "--pr"}, &out,
		&errb); code != 0 || out.String() != "https://example.test/policy/pull/7\n" {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	if len(asked) != 4 || asked[0] != "port49/offboard-ops" || asked[1] != "main" ||
		asked[2] != "chore(policy): offboard ops" || !strings.Contains(asked[3], "1 grant row(s), the subject block") {
		t.Fatalf("the pull request: %q", asked)
	}
	if !bytes.Equal(readFile(t, pol), before) {
		t.Fatal("the checkout's policy file changed")
	}
	pushed, err := runGit(remote, "show", "port49/offboard-ops:policy.yaml")
	if err != nil || strings.Contains(pushed, "name: ops") || !strings.Contains(pushed, "name: noc") {
		t.Fatalf("the pushed branch: %v\n%s", err, pushed)
	}
	if changed, _ := runGit(remote, "diff", "--name-only", "main", "port49/offboard-ops"); changed != "policy.yaml" {
		t.Fatalf("the branch changes %q", changed)
	}
	if list, _ := runGit(repo, "worktree", "list"); strings.Count(list, "\n") != 0 {
		t.Fatalf("the scratch worktree is left behind:\n%s", list)
	}
	if err := os.WriteFile(pol, append(before, []byte("# an edit in progress\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "noc", "--pr"}, &out,
		&errb); code != 1 || !strings.Contains(errb.String(), "uncommitted changes") {
		t.Fatalf("code %d %s", code, errb.String())
	}
	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "noc", "--pr",
		"--write"}, &out, &errb); code != 2 {
		t.Fatalf("--pr and --write: code %d", code)
	}
}

// The branch is cut from the base on the remote, not from the checkout's
// HEAD: an operator on a branch ahead of main gets a pull request carrying the
// removal alone, and one whose policy file differs from the base's is refused,
// because the removal was computed from a file the pull request would not
// merge into (spec §12, "the edit and nothing else").
func TestThePullRequestIsCutFromTheBase(t *testing.T) {
	repo, remote, pol, inv := gitRepo(t)
	orig := openPR
	openPR = func(dir, branch, base, title, body string) (string, error) { return "https://example.test/pull/8", nil }
	t.Cleanup(func() { openPR = orig })
	if err := os.WriteFile(filepath.Join(repo, "notes.txt"), []byte("unrelated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"checkout", "--quiet", "-b", "work"}, {"add", "notes.txt"},
		{"commit", "--quiet", "-m", "unrelated"}} {
		if _, err := runGit(repo, args...); err != nil {
			t.Fatal(err)
		}
	}
	var out, errb bytes.Buffer
	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "ops", "--pr"}, &out,
		&errb); code != 0 {
		t.Fatalf("code %d\n%s", code, errb.String())
	}
	if log, _ := runGit(remote, "log", "--format=%s", "main..port49/offboard-ops"); log != "chore(policy): offboard ops" {
		t.Fatalf("the branch carries more than the removal:\n%s", log)
	}
	if err := os.WriteFile(pol, append(readFile(t, pol), []byte("# committed here, not on main\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runGit(repo, "commit", "--quiet", "-am", "a local policy edit"); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "noc", "--pr"}, &out,
		&errb); code != 1 || !strings.Contains(errb.String(), "differs from origin/main") {
		t.Fatalf("code %d %s", code, errb.String())
	}
	errb.Reset()
	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "noc", "--pr",
		"--remote", "--receive-pack=touch /tmp/x"}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "not a remote") {
		t.Fatalf("code %d %s", code, errb.String())
	}
}

// git's own error text can carry a remote's URL, and a URL can carry a
// credential: it is removed before the error is printed.
func TestAGitErrorDoesNotPrintACredential(t *testing.T) {
	got := withoutCredentials("fatal: unable to access 'https://ci:ghp_s3cret@github.com/o/p.git/': 403")
	if strings.Contains(got, "ghp_s3cret") || !strings.Contains(got, "https://«redacted»@github.com/o/p.git/") {
		t.Fatalf("%q", got)
	}
}

// checkout is what an operator would notice changed in their repository: the
// branch they are on, its commit, the working tree's state, the local
// branches, and the worktrees.
func checkout(t *testing.T, repo string) string {
	t.Helper()
	var all []string
	for _, args := range [][]string{{"rev-parse", "--abbrev-ref", "HEAD"}, {"rev-parse", "HEAD"},
		{"status", "--porcelain", "--untracked-files=all"}, {"branch", "--list"}, {"worktree", "list", "--porcelain"}} {
		got, err := runGit(repo, args...)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, got)
	}
	return strings.Join(all, "\n--\n")
}

// A step that fails leaves the operator's checkout exactly as it was, with
// no branch of this run's left behind in it; a pull request that gh could
// not open names the branch already pushed, so the review can be opened by
// hand. Nothing is force-pushed over a branch already on the remote.
func TestAFailedStepLeavesTheCheckoutAlone(t *testing.T) {
	repo, remote, pol, inv := gitRepo(t)
	opened := 0
	orig := openPR
	openPR = func(dir, branch, base, title, body string) (string, error) {
		opened++
		return "", errors.New("gh: not logged in")
	}
	t.Cleanup(func() { openPR = orig })
	if _, err := runGit(repo, "checkout", "--quiet", "-b", "work"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "scratch.txt"), []byte("untracked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before, polBefore := checkout(t, repo), readFile(t, pol)
	unchanged := func(what string) {
		t.Helper()
		if after := checkout(t, repo); after != before {
			t.Fatalf("%s: the checkout changed:\n%s\n== was ==\n%s", what, after, before)
		}
		if !bytes.Equal(readFile(t, pol), polBefore) {
			t.Fatalf("%s: the policy file changed", what)
		}
	}
	hook := filepath.Join(remote, "hooks", "pre-receive")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\necho refused by policy >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "ops", "--pr"}, &out,
		&errb); code != 1 || !strings.Contains(errb.String(), "refused by policy") || opened != 0 {
		t.Fatalf("a refused push: code %d opened %d\n%s", code, opened, errb.String())
	}
	unchanged("a refused push")
	if err := os.Remove(hook); err != nil {
		t.Fatal(err)
	}
	errb.Reset()
	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "ops", "--pr"}, &out,
		&errb); code != 1 || !strings.Contains(errb.String(), "port49/offboard-ops is pushed to origin") ||
		!strings.Contains(errb.String(), "not logged in") {
		t.Fatalf("gh failing: code %d\n%s", code, errb.String())
	}
	unchanged("gh failing")
	pushed, err := runGit(remote, "rev-parse", "port49/offboard-ops")
	if err != nil {
		t.Fatal(err)
	}
	// The branch is on the remote now; a second run refuses rather than
	// replacing it.
	errb.Reset()
	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "ops", "--pr"}, &out,
		&errb); code != 1 || opened != 1 || !strings.Contains(errb.String(), "already on origin") {
		t.Fatalf("a second run: code %d opened %d\n%s", code, opened, errb.String())
	}
	unchanged("a second run")
	if again, _ := runGit(remote, "rev-parse", "port49/offboard-ops"); again != pushed {
		t.Fatalf("the pushed branch was replaced: %s, was %s", again, pushed)
	}
}

// Every value that reaches git's argument list has a shape refused before it
// gets there: a remote that is not one of the repository's own, a base that
// is not a plain branch name (a refspec would write a ref), and a subject
// that cannot stand in a branch name.
func TestThePullRequestRefusesWhatGitWouldMisread(t *testing.T) {
	repo, _, pol, inv := gitRepo(t)
	orig := openPR
	openPR = func(dir, branch, base, title, body string) (string, error) {
		t.Fatal("gh was run")
		return "", nil
	}
	t.Cleanup(func() { openPR = orig })
	before := checkout(t, repo)
	for _, c := range []struct {
		flags []string
		want  string
	}{
		{[]string{"--remote", "upstream"}, "not a remote"},
		{[]string{"--remote", "../remote.git"}, "not a remote"},
		{[]string{"--remote", "-oProxyCommand=touch /tmp/x"}, "not a remote"},
		{[]string{"--base", "-x"}, "not a branch"},
		{[]string{"--base", "main:refs/heads/elsewhere"}, "not a branch"},
		{[]string{"--base", "+main"}, "not a branch"},
		{[]string{"--base", "main~1"}, "not a branch"},
		{[]string{"--base", ""}, "not a branch"},
	} {
		var out, errb bytes.Buffer
		args := append([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "ops", "--pr"},
			c.flags...)
		if code := run(args, &out, &errb); code != 1 || !strings.Contains(errb.String(), c.want) {
			t.Errorf("%q: code %d %s", c.flags, code, errb.String())
		}
	}
	if after := checkout(t, repo); after != before {
		t.Fatalf("the checkout changed:\n%s", after)
	}
	if branches, _ := runGit(repo, "for-each-ref", "--format=%(refname)", "refs/heads/elsewhere"); branches != "" {
		t.Fatalf("a ref was written: %s", branches)
	}
}

// A remote whose address carries a token: the fetch fails, and what is
// printed names the remote without the token.
func TestAFailedFetchDoesNotPrintTheRemotesCredential(t *testing.T) {
	repo, _, pol, inv := gitRepo(t)
	if _, err := runGit(repo, "remote", "add", "creds", "https://ci:ghp_s3cret@127.0.0.1:9/o/p.git"); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "ops", "--pr",
		"--remote", "creds"}, &out, &errb); code != 1 || strings.Contains(errb.String(), "ghp_s3cret") {
		t.Fatalf("code %d %s", code, errb.String())
	}
}

func TestWithoutCredentialsKeepsAURLWithoutOne(t *testing.T) {
	for in, want := range map[string]string{
		"fatal: 'https://github.com/o/p.git/' not found":       "fatal: 'https://github.com/o/p.git/' not found",
		"https://a:p@ss@host/x and ssh://git@example.test/o/p": "https://«redacted»@host/x and ssh://«redacted»@example.test/o/p",
		"to https://x-access-token:t0k@github.com/o/p.git":     "to https://«redacted»@github.com/o/p.git",
	} {
		if got := withoutCredentials(in); got != want {
			t.Errorf("%q: got %q", in, got)
		}
	}
}
