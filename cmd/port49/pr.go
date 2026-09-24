package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/rhwendt/port49/internal/platform"
	"github.com/rhwendt/port49/internal/policy"
)

// branchSafe is a subject name that can stand in a branch name as it is.
var branchSafe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// baseSafe is a branch name --base may give: path segments of plain
// characters, so no refspec (`a:b`, `+a`), revision (`a~1`, `a^`) or option
// reaches git's argument list. git check-ref-format judges the rest.
var baseSafe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*(/[A-Za-z0-9_][A-Za-z0-9._-]*)*$`)

// runGit runs git in dir, with no shell, and returns what it printed. Its
// error, the arguments with git's own words, is scrubbed of any credential in
// a URL. A test replaces nothing here: it runs real git against a scratch
// repository.
var runGit = func(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", errors.New(withoutCredentials(fmt.Sprintf("git %s: %v: %s", strings.Join(args, " "), err,
			strings.TrimSpace(errb.String()))))
	}
	return strings.TrimSpace(out.String()), nil
}

// credentialInURL is the user-information part of a URL, where a token
// pasted into a remote's address sits; it runs to the last `@` before the
// host, since a password may hold one.
var credentialInURL = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/\s]+@`)

// withoutCredentials is git's or gh's error text with any credential in a URL
// replaced: some git releases print the remote's address as configured.
func withoutCredentials(s string) string {
	return credentialInURL.ReplaceAllString(s, "${1}«redacted»@")
}

// openPR opens the pull request with the gh CLI, in dir, and returns its URL.
// The body goes on stdin, not the command line, and gh is told not to prompt:
// run unattended, it fails rather than waiting. A test replaces it: nothing
// in a test reaches GitHub.
var openPR = func(dir, branch, base, title, body string) (string, error) {
	cmd := exec.Command("gh", "pr", "create", "--head="+branch, "--base="+base, "--title="+title, "--body-file=-")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GH_PROMPT_DISABLED=1")
	cmd.Stdin = strings.NewReader(body)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("gh pr create: %v: %s", err, withoutCredentials(strings.TrimSpace(errb.String())))
	}
	return strings.TrimSpace(out.String()), nil
}

// removalPR opens the pull request `grants remove` prepares (spec §12; plan 4
// prepares the file, plan 5 opens the review): a commit on base as the remote
// has it, with the policy file edited and nothing else, pushed to remote as
// port49/offboard-<subject>, and a pull request against base. It works in a
// detached worktree of its own, so the operator's checkout, any edit in it,
// and its branches are never touched, whichever step fails. It refuses a
// policy file with uncommitted changes, which the pull request would
// otherwise silently leave out, one that differs from base's, since the
// removal was computed from a file the pull request would not merge into, and
// a branch already on the remote, which it never replaces. The title and body
// are redacted by rules, as anything quoting the policy is. It returns the
// pull request's URL, and with it an error if the scratch worktree could not
// be removed afterwards.
func removalPR(path, subject string, edited []byte, r policy.Removal, remote, base string,
	rules []platform.Redaction) (url string, err error) {
	if !branchSafe.MatchString(subject) {
		return "", fmt.Errorf("subject %q cannot name a branch; offboard it with --write and open the review by hand",
			subject)
	}
	branch := "port49/offboard-" + subject
	if _, err := runGit(filepath.Dir(path), "check-ref-format", "--branch", branch); err != nil {
		return "", fmt.Errorf("subject %q cannot name a branch; offboard it with --write and open the review by hand",
			subject)
	}
	// Both reach git's argument list: a remote must be one of the
	// repository's own, by name, and a base a plain branch name, so neither
	// is read as an option (`--receive-pack=...` runs a command), a URL, or a
	// refspec that writes a ref.
	if !baseSafe.MatchString(base) {
		return "", fmt.Errorf("--base %q is not a branch's name", base)
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", err
	}
	top, err := runGit(filepath.Dir(path), "rev-parse", "--show-toplevel")
	if err != nil {
		return "", fmt.Errorf("the policy file is not in a git repository: %w", err)
	}
	if _, err := runGit(top, "check-ref-format", "refs/heads/"+base); err != nil {
		return "", fmt.Errorf("--base %q is not a branch's name", base)
	}
	remotes, err := runGit(top, "remote")
	if err != nil {
		return "", err
	}
	known := false
	for _, name := range strings.Split(remotes, "\n") {
		known = known || (name != "" && name == remote)
	}
	if !known {
		return "", fmt.Errorf("--remote %q is not a remote of %s; `git remote` lists them", remote, top)
	}
	rel, err := filepath.Rel(top, path)
	if err != nil {
		return "", err
	}
	if dirty, err := runGit(top, "status", "--porcelain", "--", rel); err != nil {
		return "", err
	} else if dirty != "" {
		return "", errors.New("the policy file has uncommitted changes; commit or discard them first, so the pull " +
			"request carries the removal and nothing else")
	}
	if _, err := runGit(top, "fetch", "--quiet", "--", remote, "refs/heads/"+base); err != nil {
		return "", err
	}
	from, err := runGit(top, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	if err != nil {
		return "", err
	}
	here, _ := runGit(top, "rev-parse", "HEAD:"+filepath.ToSlash(rel))
	there, _ := runGit(top, "rev-parse", from+":"+filepath.ToSlash(rel))
	if here == "" || here != there {
		return "", fmt.Errorf("the policy file differs from %s/%s; the removal is computed from your checkout's "+
			"copy, so bring it level with %s/%s first, and the pull request carries the removal and nothing else",
			remote, base, remote, base)
	}
	if on, err := runGit(top, "ls-remote", "--heads", "--", remote, "refs/heads/"+branch); err != nil {
		return "", err
	} else if on != "" {
		return "", fmt.Errorf("%s is already on %s; a review for it may be open. Delete the branch there to "+
			"start again", branch, remote)
	}
	scratch, err := os.MkdirTemp("", "port49-offboard-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(scratch)
	work := filepath.Join(scratch, "work")
	if _, err := runGit(top, "worktree", "add", "--quiet", "--detach", "--", work, from); err != nil {
		return "", err
	}
	// A worktree left behind is an entry in the operator's .git/worktrees
	// once its directory is gone; it is said, beside whatever else failed,
	// rather than dropped.
	defer func() {
		if _, rerr := runGit(top, "worktree", "remove", "--force", "--", work); rerr != nil {
			err = errors.Join(err, fmt.Errorf("the scratch worktree %s was not removed; `git worktree prune` "+
				"clears it: %w", work, rerr))
		}
	}()
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(work, rel), edited, info.Mode().Perm()); err != nil {
		return "", err
	}
	title := platform.RedactQuoted(rules, "chore(policy): offboard "+subject)
	body := platform.RedactQuoted(rules, fmt.Sprintf("`port49 grants remove --subject %s` (spec §12): %d grant "+
		"row(s), the subject block, and %d test(s) removed. The edited file loads against the inventory; run "+
		"`port49 policy test` and `port49 policy diff` in CI as for any policy change.", subject, r.Grants, r.Tests))
	if _, err := runGit(work, "commit", "--quiet", "-m", title, "-m", body, "--", rel); err != nil {
		return "", err
	}
	if _, err := runGit(work, "push", "--quiet", "--", remote, "HEAD:refs/heads/"+branch); err != nil {
		return "", err
	}
	url, err = openPR(work, branch, base, title, body)
	if err != nil {
		return "", fmt.Errorf("%s is pushed to %s, but the pull request did not open; open it against %s by "+
			"hand: %w", branch, remote, base, err)
	}
	return url, nil
}
