package ci

import (
	"go/build"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// labAcctHoldTag builds the accounting reply hold L94 cell C4 runs on
// (internal/daemon/acct/hold_lab.go). A port49d built with it delays every
// accounting reply 1.5s, so no release build may name it.
const labAcctHoldTag = "port49_lab_acct_hold"

// The default build of the accounting handler holds nothing: hold.go, not
// hold_lab.go, is in it. The release builds pass no tag but hwkey_dlopen
// (.goreleaser.yaml, Dockerfile), and this tag is named nowhere outside the
// handler's own two files, the lab harness that builds C4's binary, this
// test, and the spec and plan text that describe it.
func TestNoReleaseBuildNamesTheAccountingHoldTag(t *testing.T) {
	ctx := build.Default
	ctx.BuildTags = []string{"hwkey_dlopen"}
	pkg, err := ctx.ImportDir(filepath.Join("..", "..", "internal", "daemon", "acct"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(pkg.GoFiles, "hold.go") || slices.Contains(pkg.GoFiles, "hold_lab.go") {
		t.Fatalf("the release build of internal/daemon/acct has %v: want hold.go and not hold_lab.go", pkg.GoFiles)
	}

	allowed := func(rel string) bool {
		switch {
		case rel == "internal/daemon/acct/hold.go", rel == "internal/daemon/acct/hold_lab.go",
			rel == "internal/daemon/acct/hold_test.go", rel == "tests/ci/lab_hold_test.go":
			return true
		case strings.HasPrefix(rel, "tests/lab/") && strings.HasSuffix(rel, ".go"):
			return true
		case strings.HasPrefix(rel, "docs/") && strings.HasSuffix(rel, ".md"):
			return true
		}
		return false
	}
	// The tracked tree is what a release builds from: untracked scratch
	// (a worktree's notes, a local build) is no release input.
	root := filepath.Join("..", "..")
	out, err := exec.Command("git", "-C", root, "ls-files", "-z").Output()
	if err != nil {
		t.Fatalf("git ls-files: %v", err)
	}
	found := 0
	for _, rel := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		name := path.Base(rel)
		// Never read a credential file.
		if name == "realm.json" || strings.HasSuffix(name, ".env") || strings.HasSuffix(name, "-key.pem") ||
			strings.HasSuffix(name, ".keytab") {
			continue
		}
		p := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Lstat(p)
		if err != nil || info.Size() > 4<<20 || !info.Mode().IsRegular() {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if strings.Contains(string(b), labAcctHoldTag) {
			found++
			if !allowed(rel) {
				t.Errorf("%s names the lab-only build tag %s: no build outside the lab may", rel, labAcctHoldTag)
			}
		}
	}
	if found < 3 {
		t.Fatalf("the tag was found in %d files: the scan is broken", found)
	}
}
