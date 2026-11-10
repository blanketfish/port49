// Command docspublish decides what the docs workflow deploys for a ref: whether to publish, the
// site's banner, the mike version to publish it as, and the aliases that version takes. It prints
// publish=true|false, banner=<text>, version=<name> and aliases=<space-separated, may be empty> in
// the form $GITHUB_OUTPUT takes. Run from the repository root with the full history and tags fetched.
//
// The site has one copy per version (mike, on the gh-pages branch):
//
//   - main publishes "dev" on every push. It also takes the "latest" alias, but only while no final
//     release tag exists, so that /latest/ always resolves. With -sha, a commit that is no longer
//     main's tip publishes nothing: a newer main push deploys, and a re-run of an older run must not
//     put its older docs back.
//   - a final release tag vX.Y.Z that is an ancestor of main publishes "X.Y", but only if it is the
//     highest patch of its X.Y line: a lower tag pushed late, or a re-run of an old one, must not
//     overwrite newer docs. It takes "latest" only if it is also the highest final tag overall.
//   - only final tags that are ancestors of main count, in every rule above: a stray tag on another
//     branch neither takes "latest" nor outranks a real release.
//   - every other ref, a pull request included, builds only and carries the main banner, so the
//     banner is never empty.
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

// result is what the workflow deploys: Version is empty and Aliases empty unless Publish is true.
type result struct {
	Publish bool
	Banner  string
	Version string // the mike version: "dev" or "X.Y"
	Aliases string // space-separated mike aliases
}

// decide is what ref deploys. mainRef is the ref a release tag's commit must be an ancestor of.
// sha is the commit the run builds; for main, a commit that is not mainRef's tip does not publish.
func decide(dir, ref, mainRef, sha string) (result, error) {
	noPublish := result{Banner: mainBanner}
	git := func(args ...string) (string, error) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.Output()
		return string(out), err
	}
	// onMain is whether the commit of ref is an ancestor of mainRef.
	onMain := func(ref string) (bool, error) {
		cmd := exec.Command("git", "merge-base", "--is-ancestor", ref, mainRef)
		cmd.Dir = dir
		switch err := cmd.Run().(type) {
		case nil:
			return true, nil
		case *exec.ExitError:
			if err.ExitCode() == 1 {
				return false, nil
			}
			return false, fmt.Errorf("git merge-base: %w", err)
		default:
			return false, fmt.Errorf("git merge-base: %w", err)
		}
	}
	// finalTags is every final release tag that is an ancestor of mainRef: a stray tag on another
	// branch is not a release of the site, so it cannot take latest or outrank a real release.
	finalTags := func() ([]string, error) {
		out, err := git("tag", "-l", "v*")
		if err != nil {
			return nil, fmt.Errorf("git tag -l: %w", err)
		}
		var tags []string
		for _, tag := range strings.Fields(out) {
			if !releaseTag.MatchString(tag) {
				continue
			}
			ok, err := onMain("refs/tags/" + tag)
			if err != nil {
				return nil, err
			}
			if ok {
				tags = append(tags, tag)
			}
		}
		return tags, nil
	}
	switch {
	case ref == "refs/heads/main":
		// a run for an older main commit, or a re-run of one, would put older docs back on dev (and on
		// latest, before the first release): the newer main push deploys instead
		if sha != "" {
			commit, err := git("rev-parse", "--verify", "--end-of-options", sha+"^{commit}")
			if err != nil {
				return result{}, fmt.Errorf("git rev-parse %s: %w", sha, err)
			}
			tip, err := git("rev-parse", "--verify", "--end-of-options", mainRef+"^{commit}")
			if err != nil {
				return result{}, fmt.Errorf("git rev-parse %s: %w", mainRef, err)
			}
			if commit != tip {
				return noPublish, nil
			}
		}
		tags, err := finalTags()
		if err != nil {
			return result{}, err
		}
		r := result{Publish: true, Banner: mainBanner, Version: "dev"}
		if len(tags) == 0 {
			r.Aliases = "latest"
		}
		return r, nil
	case strings.HasPrefix(ref, "refs/tags/"):
		tag := strings.TrimPrefix(ref, "refs/tags/")
		if !releaseTag.MatchString(tag) {
			return noPublish, nil
		}
		tags, err := finalTags()
		if err != nil {
			return result{}, err
		}
		latest := true
		for _, other := range tags {
			if !newer(other, tag) {
				continue
			}
			// a lower patch pushed late, or a re-run of one, must not overwrite its line's newer docs
			if line(other) == line(tag) {
				return noPublish, nil
			}
			latest = false
		}
		ok, err := onMain(ref)
		if err != nil {
			return result{}, err
		}
		if !ok {
			return noPublish, nil
		}
		r := result{Publish: true, Banner: "This site describes port49 " + tag + ".", Version: line(tag)}
		if latest {
			r.Aliases = "latest"
		}
		return r, nil
	}
	return noPublish, nil
}

// line is the X.Y of final tag vX.Y.Z, the mike version of its docs.
func line(tag string) string {
	parts := strings.Split(tag[1:], ".")
	return parts[0] + "." + parts[1]
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

func format(r result) string {
	return fmt.Sprintf("publish=%t\nbanner=%s\nversion=%s\naliases=%s\n", r.Publish, r.Banner, r.Version, r.Aliases)
}

func main() {
	fs := flag.NewFlagSet("docspublish", flag.ContinueOnError)
	ref := fs.String("ref", "", "the ref the workflow runs for, as $GITHUB_REF")
	dir := fs.String("dir", ".", "the repository root")
	mainRef := fs.String("main", "origin/main", "the ref a release tag must be on, and main's tip")
	sha := fs.String("sha", "", "the commit the run builds, as $GITHUB_SHA; for main, only the tip of -main publishes")
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	r, err := decide(*dir, *ref, *mainRef, *sha)
	if err != nil {
		fmt.Fprintln(os.Stderr, "docspublish:", err)
		os.Exit(1)
	}
	// main publishes on every push unless its commit is no longer main's tip
	if *ref == "refs/heads/main" && !r.Publish {
		fmt.Fprintln(os.Stderr, "docspublish: a newer main push deploys")
	}
	fmt.Print(format(r))
}
