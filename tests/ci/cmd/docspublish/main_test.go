package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// wantMain is spelled out here, not taken from main.go, so a change to the text fails a test.
const wantMain = "This site describes port49 as it is on main, not a release."

// git runs git in dir with a fixed identity and no user config, and returns its output.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// repo is a repository with one commit on main; the returned dir is its root.
func repo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	git(t, dir, "commit", "-q", "--allow-empty", "-m", "first")
	return dir
}

func TestDocsPublish(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, dir string)
		ref     string
		publish bool
		banner  string
	}{
		{"main with no release tag", func(t *testing.T, d string) {}, "refs/heads/main", true, wantMain},
		{"main with a release tag", func(t *testing.T, d string) { git(t, d, "tag", "v0.1.0") }, "refs/heads/main", false, wantMain},
		{"main with only a pre-release tag", func(t *testing.T, d string) { git(t, d, "tag", "v0.1.0-rc1") }, "refs/heads/main", true, wantMain},
		{"a release tag on main", func(t *testing.T, d string) { git(t, d, "tag", "v0.1.0") }, "refs/tags/v0.1.0", true, "This site describes port49 v0.1.0."},
		{"a release tag off main", func(t *testing.T, d string) {
			git(t, d, "checkout", "-q", "-b", "side")
			git(t, d, "commit", "-q", "--allow-empty", "-m", "side")
			git(t, d, "tag", "v0.1.0")
			git(t, d, "checkout", "-q", "main")
		}, "refs/tags/v0.1.0", false, wantMain},
		{"a pull request", func(t *testing.T, d string) {}, "refs/pull/7/merge", false, wantMain},
		{"another branch", func(t *testing.T, d string) {}, "refs/heads/feature/x", false, wantMain},
		{"an empty ref", func(t *testing.T, d string) {}, "", false, wantMain},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := repo(t)
			c.setup(t, d)
			publish, banner, err := decide(d, c.ref, "main")
			if err != nil {
				t.Fatal(err)
			}
			if publish != c.publish || banner != c.banner {
				t.Errorf("decide(%q) = %v, %q; want %v, %q", c.ref, publish, banner, c.publish, c.banner)
			}
			if banner == "" {
				t.Error("the banner is empty")
			}
		})
	}
}

func TestAPrereleaseTagIsNotARelease(t *testing.T) {
	for _, tag := range []string{"v0.1.0-rc1", "v0.1.0-beta.2", "v0.1.0rc1", "v1", "v0.1", "v0.1.0.1"} {
		t.Run(tag, func(t *testing.T) {
			d := repo(t)
			git(t, d, "tag", tag)
			publish, banner, err := decide(d, "refs/tags/"+tag, "main")
			if err != nil {
				t.Fatal(err)
			}
			if publish || banner != wantMain {
				t.Errorf("%s: publish %v, banner %q; want false and the main banner", tag, publish, banner)
			}
			// present in git tag -l, it does not stop main's deploys
			if publish, _, _ := decide(d, "refs/heads/main", "main"); !publish {
				t.Errorf("%s stops main's deploys", tag)
			}
		})
	}
	for tag, banner := range map[string]string{
		"v0.1.0":    "This site describes port49 v0.1.0.",
		"v10.20.30": "This site describes port49 v10.20.30.",
	} {
		t.Run(tag, func(t *testing.T) {
			d := repo(t)
			git(t, d, "tag", tag)
			publish, got, err := decide(d, "refs/tags/"+tag, "main")
			if err != nil {
				t.Fatal(err)
			}
			if !publish || got != banner {
				t.Errorf("%s: publish %v, banner %q; want true and %q", tag, publish, got, banner)
			}
			if publish, _, _ := decide(d, "refs/heads/main", "main"); publish {
				t.Errorf("%s does not stop main's deploys", tag)
			}
		})
	}
}

func TestTheOutputIsTwoOutputLines(t *testing.T) {
	if got, want := format(true, "b"), "publish=true\nbanner=b\n"; got != want {
		t.Errorf("format = %q, want %q", got, want)
	}
	if got, want := format(false, wantMain), "publish=false\nbanner="+wantMain+"\n"; got != want {
		t.Errorf("format = %q, want %q", got, want)
	}
}
