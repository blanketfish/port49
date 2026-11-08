// Command docspublish decides whether the docs workflow deploys the site for a ref, and what
// the site's banner says. It prints publish=true|false and banner=<text> in the form
// $GITHUB_OUTPUT takes. Run from the repository root with the full history and tags fetched.
//
// Only the highest final release tag (vX.Y.Z, compared numerically) deploys and moves the banner to that version. main deploys
// until the first release tag exists. Every other ref, a pull request included, builds only and
// carries the main banner, so the banner is never empty.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

const mainBanner = "This site describes port49 as it is on main, not a release."

// releaseTag matches a final version whole: a pre-release, a suffix without a hyphen and a short
// form are all something else.
var releaseTag = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// decide is whether ref publishes and the banner to build with. mainRef is the ref a release
// tag's commit must be an ancestor of.
func decide(dir, ref, mainRef string) (bool, string, error) {
	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.Output()
		return string(out), err
	}
	switch {
	case ref == "refs/heads/main":
		tags, err := git("tag", "-l", "v*")
		if err != nil {
			return false, "", fmt.Errorf("git tag -l: %w", err)
		}
		for _, tag := range strings.Fields(tags) {
			if releaseTag.MatchString(tag) {
				return false, mainBanner, nil
			}
		}
		return true, mainBanner, nil
	case strings.HasPrefix(ref, "refs/tags/"):
		tag := strings.TrimPrefix(ref, "refs/tags/")
		if !releaseTag.MatchString(tag) {
			return false, mainBanner, nil
		}
		tags, err := git("tag", "-l", "v*")
		if err != nil {
			return false, "", fmt.Errorf("git tag -l: %w", err)
		}
		// a lower tag pushed late, or a re-run of an old one, must not overwrite newer docs
		for _, other := range strings.Fields(tags) {
			if releaseTag.MatchString(other) && newer(other, tag) {
				return false, mainBanner, nil
			}
		}
		cmd := exec.Command("git", "merge-base", "--is-ancestor", ref, mainRef)
		cmd.Dir = dir
		switch err := cmd.Run().(type) {
		case nil:
			return true, "This site describes port49 " + tag + ".", nil
		case *exec.ExitError:
			if err.ExitCode() == 1 { // not an ancestor
				return false, mainBanner, nil
			}
			return false, "", fmt.Errorf("git merge-base: %w", err)
		default:
			return false, "", fmt.Errorf("git merge-base: %w", err)
		}
	}
	return false, mainBanner, nil
}

// newer is whether final tag a is a higher version than final tag b, compared numerically.
func newer(a, b string) bool {
	pa, pb := strings.Split(a[1:], "."), strings.Split(b[1:], ".")
	for i := range pa {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x > y
		}
	}
	return false
}

func format(publish bool, banner string) string {
	return fmt.Sprintf("publish=%t\nbanner=%s\n", publish, banner)
}

func main() {
	fs := flag.NewFlagSet("docspublish", flag.ContinueOnError)
	ref := fs.String("ref", "", "the ref the workflow runs for, as $GITHUB_REF")
	dir := fs.String("dir", ".", "the repository root")
	mainRef := fs.String("main", "origin/main", "the ref a release tag must be on")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	publish, banner, err := decide(*dir, *ref, *mainRef)
	if err != nil {
		fmt.Fprintln(os.Stderr, "docspublish:", err)
		os.Exit(1)
	}
	fmt.Print(format(publish, banner))
}
