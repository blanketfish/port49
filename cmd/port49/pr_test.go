package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/policy"
)

// gitRepo is a scratch repository holding the policy fixture, committed on
// main, with a bare repository as its origin. origin's address is
// ssh://example.test/o/p.git, as a GitHub remote's would be, and ssh is a
// script that serves that one path from the bare repository, so the pull
// request's repository is read from a real push URL. Identity and signing are set
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
	ssh := filepath.Join(root, "ssh")
	script := "#!/bin/sh\n[ \"${2#* }\" = \"'/o/p.git'\" ] || { echo \"ssh: no repository at $2\" >&2; exit 1; }\n" +
		"sub=${2%% *}\nexec git \"${sub#git-}\" '" + remote + "'\n"
	if err := os.WriteFile(ssh, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_SSH_COMMAND", ssh)
	t.Setenv("GIT_SSH_VARIANT", "simple")
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
		{"remote", "add", "origin", "ssh://example.test/o/p.git"}, {"push", "--quiet", "origin", "main"}} {
		if _, err := runGit(repo, args...); err != nil {
			t.Fatal(err)
		}
	}
	// gh is never run in a test: a test that expects the pull request to
	// open replaces this with a fake of its own.
	orig := openPR
	openPR = func(dir, repo, branch, base, title, body string) (string, error) {
		t.Fatal("gh was run")
		return "", nil
	}
	t.Cleanup(func() { openPR = orig })
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
	openPR = func(dir, repo, branch, base, title, body string) (string, error) {
		asked = []string{repo, branch, base, title, body}
		return "https://example.test/policy/pull/7", nil
	}
	t.Cleanup(func() { openPR = orig })
	var out, errb bytes.Buffer
	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "ops", "--pr"}, &out,
		&errb); code != 0 || out.String() != "https://example.test/policy/pull/7\n" {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
	if len(asked) != 5 || asked[0] != "example.test/o/p" || asked[1] != "port49/offboard-ops" || asked[2] != "main" ||
		asked[3] != "chore(policy): offboard ops" || !strings.Contains(asked[4], "1 grant row(s), the subject block") {
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
	openPR = func(dir, _, branch, base, title, body string) (string, error) {
		return "https://example.test/pull/8", nil
	}
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
	openPR = func(dir, _, branch, base, title, body string) (string, error) {
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
		"fatal: 'https://github.com/o/p.git/' not found":        "fatal: 'https://github.com/o/p.git/' not found",
		"https://a:p@ss@host/x and ssh://git@example.test/o/p":  "https://«redacted»@host/x and ssh://«redacted»@example.test/o/p",
		"fatal: 'ci:ghp_s3cret@github.com:o/p' does not appear": "fatal: '«redacted»@github.com:o/p' does not appear",
		"https://u:p/w@github.com/o/p":                          "https://«redacted»@github.com/o/p",
		"git@github.com:o/p.git":                                "git@github.com:o/p.git",
		"to https://x-access-token:t0k@github.com/o/p.git":      "to https://«redacted»@github.com/o/p.git",
	} {
		if got := withoutCredentials(in); got != want {
			t.Errorf("%q: got %q", in, got)
		}
	}
}

// A subject of branch-safe characters can still make no branch name (`a..b`,
// `x.lock`); it is refused before git fetches or writes anything.
func TestASubjectThatCannotNameABranchIsRefusedFirst(t *testing.T) {
	repo, _, pol, _ := gitRepo(t)
	for _, subject := range []string{"a..b", "x.lock", "x."} {
		_, err := removalPR(pol, subject, nil, policy.Removal{}, "origin", "main", nil)
		if err == nil || !strings.Contains(err.Error(), "cannot name a branch") {
			t.Errorf("%q: %v", subject, err)
		}
	}
	if _, err := os.Stat(filepath.Join(repo, ".git", "FETCH_HEAD")); !os.IsNotExist(err) {
		t.Fatalf("git fetched: %v", err)
	}
}

// A scratch worktree git will not remove is said, with the pull request's URL
// when it opened, and beside gh's error when it did not.
func TestAWorktreeLeftBehindIsSaid(t *testing.T) {
	for _, ghFails := range []bool{false, true} {
		repo, _, pol, inv := gitRepo(t)
		orig := openPR
		openPR = func(dir, _, branch, base, title, body string) (string, error) {
			if _, err := runGit(repo, "worktree", "lock", "--", dir); err != nil {
				t.Fatal(err)
			}
			if ghFails {
				return "", errors.New("gh: not logged in")
			}
			return "https://example.test/pull/9", nil
		}
		t.Cleanup(func() { openPR = orig })
		var out, errb bytes.Buffer
		code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "ops", "--pr"}, &out,
			&errb)
		if code != 1 || !strings.Contains(errb.String(), "was not removed; `git worktree prune` clears it") ||
			!strings.Contains(errb.String(), "locked") {
			t.Fatalf("gh fails %v: code %d\n%s", ghFails, code, errb.String())
		}
		if ghFails && (!strings.Contains(errb.String(), "not logged in") || out.Len() != 0) {
			t.Fatalf("gh's error: %q %s", out.String(), errb.String())
		}
		if !ghFails && out.String() != "https://example.test/pull/9\n" {
			t.Fatalf("the URL: %q", out.String())
		}
	}
}

// The pull request is opened in the repository the branch is pushed to, as
// `git remote get-url --push` has it after pushurl and insteadOf, never in
// one gh would pick for itself (in a fork's checkout, often the upstream). A
// push URL that names no HOST/OWNER/REPO refuses --pr before git fetches.
func TestThePullRequestGoesWhereTheBranchIsPushed(t *testing.T) {
	repo, remote, pol, inv := gitRepo(t)
	var opened []string
	orig := openPR
	openPR = func(dir, target, branch, base, title, body string) (string, error) {
		opened = append(opened, target)
		return "https://example.test/pull/10", nil
	}
	t.Cleanup(func() { openPR = orig })
	for _, args := range [][]string{
		{"remote", "add", "mirror", "https://example.test/m/p.git"},
		{"config", "url." + remote + ".insteadOf", "https://example.test/m/p.git"},
		{"remote", "add", "path", remote},
		{"remote", "add", "file", "file://" + remote},
		{"remote", "add", "elsewhere", "ssh://example.test/o/p.git"},
		{"remote", "set-url", "--push", "elsewhere", remote},
		{"remote", "add", "creds", "https://ci:ghp_s3cret@example.test/no-owner"},
		{"remote", "add", "scpcreds", "ci:ghp_s3cret@example.test:no-owner"},
		{"remote", "add", "slashcreds", "https://ci:ghp/s3cret@example.test/no-owner"},
		{"remote", "add", "fetchpath", remote},
		{"remote", "set-url", "--push", "fetchpath", "ssh://example.test/o/p.git"},
	} {
		if _, err := runGit(repo, args...); err != nil {
			t.Fatal(err)
		}
	}
	before := checkout(t, repo)
	// The refusal names the remote, never its URL: a URL malformed enough to
	// refuse may hold a credential no pattern recognizes.
	for _, name := range []string{"mirror", "path", "file", "elsewhere", "creds", "scpcreds", "slashcreds"} {
		var out, errb bytes.Buffer
		if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "ops", "--pr",
			"--remote", name}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "names no repository") ||
			!strings.Contains(errb.String(), "git remote get-url --push "+name) || strings.Contains(errb.String(), "s3cret") ||
			strings.Contains(errb.String(), "example.test") || strings.Contains(errb.String(), remote) {
			t.Errorf("--remote %s: code %d %s", name, code, errb.String())
		}
	}
	if _, err := os.Stat(filepath.Join(repo, ".git", "FETCH_HEAD")); !os.IsNotExist(err) || len(opened) != 0 {
		t.Fatalf("git fetched (%v) or gh ran (%q)", err, opened)
	}
	if after := checkout(t, repo); after != before {
		t.Fatalf("the checkout changed:\n%s", after)
	}
	// Fetched from a path, pushed over ssh: the push URL names the repository.
	var out, errb bytes.Buffer
	if code := run([]string{"grants", "remove", "--policy", pol, "--inventory", inv, "--subject", "ops", "--pr",
		"--remote", "fetchpath"}, &out, &errb); code != 0 || len(opened) != 1 || opened[0] != "example.test/o/p" {
		t.Fatalf("code %d %q\n%s", code, opened, errb.String())
	}
}

func TestGHRepoReadsWhatGitHubServes(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/o/p.git":                    "github.com/o/p",
		"https://github.com/o/p":                        "github.com/o/p",
		"https://github.com/o/p.git/":                   "github.com/o/p",
		"https://x-access-token:t0k@github.com/o/p.git": "github.com/o/p",
		"https://GHE.Example.test:8443/team/policy.git": "ghe.example.test/team/policy",
		"ssh://git@github.com/o/p.git":                  "github.com/o/p",
		"ssh://git@ssh.github.com:443/o/p.git":          "github.com/o/p",
		"git@github.com:o/p.git":                        "github.com/o/p",
		"git@github.com:o/p.git/":                       "github.com/o/p",
		"github.com:o/p":                                "github.com/o/p",
		"/srv/git/o/p.git":                              "",
		"../remote.git":                                 "",
		"file:///srv/o/p.git":                           "",
		"git://github.com/o/p.git":                      "",
		"https://github.com/o":                          "",
		"https://github.com/o/p/q":                      "",
		"https://github.com//p":                         "",
		"https://github.com/o/..":                       "",
		"git@github.com:/o/p.git":                       "",
		"origin":                                        "",
		"C:/repos/o/p":                                  "",
		"https://-oProxyCommand=x/o/p":                  "",
		"https://github.com/-o/p":                       "",
		"https://github.com/o/-p":                       "",
		"git@github.com:-o/p":                           "",
	} {
		got, ok := ghRepo(in)
		if got != want || ok != (want != "") {
			t.Errorf("%q: got %q %v, want %q", in, got, ok, want)
		}
	}
}
