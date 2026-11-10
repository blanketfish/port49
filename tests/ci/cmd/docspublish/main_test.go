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

// tagged commits and tags each tag on main, in order, so a later tag is a descendant of an earlier one.
func tagged(t *testing.T, d string, tags ...string) {
	t.Helper()
	for _, tag := range tags {
		git(t, d, "commit", "-q", "--allow-empty", "-m", tag)
		git(t, d, "tag", tag)
	}
}

func TestDocsPublish(t *testing.T) {
	cases := []struct {
		name    string
		setup   func(t *testing.T, dir string)
		ref     string
		publish bool
		banner  string
		version string
		aliases string
	}{
		// main publishes dev on every push; latest follows it only until a release exists
		{"main with no release tag", func(t *testing.T, d string) {}, "refs/heads/main", true, wantMain, "dev", "latest"},
		{"main with a release tag", func(t *testing.T, d string) { git(t, d, "tag", "v0.1.0") }, "refs/heads/main", true, wantMain, "dev", ""},
		{"main with only a pre-release tag", func(t *testing.T, d string) { git(t, d, "tag", "v0.1.0-rc1") }, "refs/heads/main", true, wantMain, "dev", "latest"},
		{"a release tag on main", func(t *testing.T, d string) { git(t, d, "tag", "v0.1.0") }, "refs/tags/v0.1.0", true, "This site describes port49 v0.1.0.", "0.1", "latest"},
		{"a release tag off main", func(t *testing.T, d string) {
			git(t, d, "checkout", "-q", "-b", "side")
			git(t, d, "commit", "-q", "--allow-empty", "-m", "side")
			git(t, d, "tag", "v0.1.0")
			git(t, d, "checkout", "-q", "main")
		}, "refs/tags/v0.1.0", false, wantMain, "", ""},
		{"a pull request", func(t *testing.T, d string) {}, "refs/pull/7/merge", false, wantMain, "", ""},
		{"another branch", func(t *testing.T, d string) {}, "refs/heads/feature/x", false, wantMain, "", ""},
		{"an empty ref", func(t *testing.T, d string) {}, "", false, wantMain, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := repo(t)
			c.setup(t, d)
			got, err := decide(d, c.ref, "main")
			if err != nil {
				t.Fatal(err)
			}
			want := result{c.publish, c.banner, c.version, c.aliases}
			if got != want {
				t.Errorf("decide(%q) = %+v; want %+v", c.ref, got, want)
			}
			if got.Banner == "" {
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
			got, err := decide(d, "refs/tags/"+tag, "main")
			if err != nil {
				t.Fatal(err)
			}
			if got != (result{false, wantMain, "", ""}) {
				t.Errorf("%s: %+v; want no publish, the main banner, no version", tag, got)
			}
			// present in git tag -l, it does not take latest from main's deploys
			if m, _ := decide(d, "refs/heads/main", "main"); !m.Publish || m.Version != "dev" || m.Aliases != "latest" {
				t.Errorf("%s changes main's deploy: %+v", tag, m)
			}
		})
	}
	for tag, want := range map[string]result{
		"v0.1.0":    {true, "This site describes port49 v0.1.0.", "0.1", "latest"},
		"v10.20.30": {true, "This site describes port49 v10.20.30.", "10.20", "latest"},
	} {
		t.Run(tag, func(t *testing.T) {
			d := repo(t)
			git(t, d, "tag", tag)
			got, err := decide(d, "refs/tags/"+tag, "main")
			if err != nil {
				t.Fatal(err)
			}
			if got != want {
				t.Errorf("%s: %+v; want %+v", tag, got, want)
			}
			if m, _ := decide(d, "refs/heads/main", "main"); !m.Publish || m.Version != "dev" || m.Aliases != "" {
				t.Errorf("%s: main publishes %+v, want dev with no alias", tag, m)
			}
		})
	}
}

// Each X.Y line deploys only its highest patch, and only the highest final tag overall takes the
// latest alias: a lower tag pushed late, or its workflow re-run, would overwrite newer docs.
// Versions compare numerically.
func TestOnlyTheHighestPatchOfALineDeploys(t *testing.T) {
	for _, c := range []struct {
		name    string
		tags    []string
		ref     string
		publish bool
		version string
		aliases string
	}{
		{"v0.1.9 pushed after v0.2.0 is a lower line and still the line's highest", []string{"v0.2.0", "v0.1.9"}, "refs/tags/v0.1.9", true, "0.1", ""},
		{"v0.2.0 after v0.1.9", []string{"v0.1.9", "v0.2.0"}, "refs/tags/v0.2.0", true, "0.2", "latest"},
		{"v0.1.9 after v0.1.10 loses to its own line", []string{"v0.1.10", "v0.1.9"}, "refs/tags/v0.1.9", false, "", ""},
		{"v0.1.10 against v0.1.9", []string{"v0.1.9", "v0.1.10"}, "refs/tags/v0.1.10", true, "0.1", "latest"},
		{"v0.1.0 after v0.1.1", []string{"v0.1.1", "v0.1.0"}, "refs/tags/v0.1.0", false, "", ""},
		{"v0.1.1 supersedes v0.1.0 in the same line", []string{"v0.1.0", "v0.1.1"}, "refs/tags/v0.1.1", true, "0.1", "latest"},
		{"a patch of an older line takes no latest", []string{"v0.2.0", "v0.1.0", "v0.1.1"}, "refs/tags/v0.1.1", true, "0.1", ""},
		{"v0.10.0 against v0.9.0", []string{"v0.9.0", "v0.10.0"}, "refs/tags/v0.10.0", true, "0.10", "latest"},
		{"v0.9.0 against v0.10.0", []string{"v0.10.0", "v0.9.0"}, "refs/tags/v0.9.0", true, "0.9", ""},
		{"the major version counts", []string{"v1.0.0", "v0.99.99"}, "refs/tags/v0.99.99", true, "0.99", ""},
		{"a higher pre-release does not count", []string{"v0.1.0", "v0.2.0-rc1", "v1"}, "refs/tags/v0.1.0", true, "0.1", "latest"},
		{"a re-run of the only tag", []string{"v0.1.0"}, "refs/tags/v0.1.0", true, "0.1", "latest"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := repo(t)
			tagged(t, d, c.tags...)
			got, err := decide(d, c.ref, "main")
			if err != nil {
				t.Fatal(err)
			}
			if got.Publish != c.publish || got.Version != c.version || got.Aliases != c.aliases {
				t.Errorf("decide = %+v, want publish %v version %q aliases %q", got, c.publish, c.version, c.aliases)
			}
			if !got.Publish && got.Banner != wantMain {
				t.Errorf("banner = %q, want the main banner", got.Banner)
			}
		})
	}
}

// A final tag that is not on main (a stray, a deleted release branch's) is not a release of the site:
// it must not take latest from the real releases, outrank a patch, or stop main's latest.
func TestOnlyTagsOnMainCount(t *testing.T) {
	// stray tags v9.9.9 and v0.1.5 sit on a side branch off main
	stray := func(t *testing.T, d string) {
		git(t, d, "checkout", "-q", "-b", "side")
		tagged(t, d, "v9.9.9", "v0.1.5")
		git(t, d, "checkout", "-q", "main")
	}
	for _, c := range []struct {
		name  string
		setup func(t *testing.T, d string)
		ref   string
		want  result
	}{
		{"main with only a stray tag still takes latest", func(t *testing.T, d string) { stray(t, d) },
			"refs/heads/main", result{true, wantMain, "dev", "latest"}},
		{"main with a real release does not", func(t *testing.T, d string) { stray(t, d); tagged(t, d, "v0.1.0") },
			"refs/heads/main", result{true, wantMain, "dev", ""}},
		{"a real release takes latest from a higher stray", func(t *testing.T, d string) { stray(t, d); tagged(t, d, "v0.1.0") },
			"refs/tags/v0.1.0", result{true, "This site describes port49 v0.1.0.", "0.1", "latest"}},
		{"a higher stray patch does not stop its line", func(t *testing.T, d string) { stray(t, d); tagged(t, d, "v0.1.0") },
			"refs/tags/v0.1.0", result{true, "This site describes port49 v0.1.0.", "0.1", "latest"}},
		{"the stray itself publishes nothing", func(t *testing.T, d string) { stray(t, d); tagged(t, d, "v0.1.0") },
			"refs/tags/v9.9.9", result{false, wantMain, "", ""}},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := repo(t)
			c.setup(t, d)
			got, err := decide(d, c.ref, "main")
			if err != nil {
				t.Fatal(err)
			}
			if got != c.want {
				t.Errorf("decide(%q) = %+v, want %+v", c.ref, got, c.want)
			}
		})
	}
}

func TestTheOutputIsFourOutputLines(t *testing.T) {
	if got, want := format(result{true, "b", "0.1", "latest"}), "publish=true\nbanner=b\nversion=0.1\naliases=latest\n"; got != want {
		t.Errorf("format = %q, want %q", got, want)
	}
	if got, want := format(result{true, wantMain, "dev", ""}), "publish=true\nbanner="+wantMain+"\nversion=dev\naliases=\n"; got != want {
		t.Errorf("format = %q, want %q", got, want)
	}
	if got, want := format(result{false, wantMain, "", ""}), "publish=false\nbanner="+wantMain+"\nversion=\naliases=\n"; got != want {
		t.Errorf("format = %q, want %q", got, want)
	}
}
