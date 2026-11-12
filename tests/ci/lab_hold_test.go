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
// (internal/daemon/acct/hold_lab.go). A port49d built with it delays accounting
// replies 1.5s while a control file exists, so no release build may name it.
const labAcctHoldTag = "port49_lab_acct_hold"

// The default build of the accounting handler holds nothing: hold.go, not
// hold_lab.go, is in it. The release builds pass no tag but hwkey_dlopen
// (.goreleaser.yaml, Dockerfile), and this tag is named nowhere outside the
// handler's own two files and their tests, the lab harness that builds C4's
// binary, this test, the spec and plan text that describe it, and the lab
// evidence that records a c4 run.
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
			if !labHoldTagAllowed(rel) {
				t.Errorf("%s names the lab-only build tag %s: no build outside the lab may", rel, labAcctHoldTag)
			}
		}
	}
	if found < 3 {
		t.Fatalf("the tag was found in %d files: the scan is broken", found)
	}
}

// labHoldTagAllowed is the tracked files that may name the hold tag.
func labHoldTagAllowed(rel string) bool {
	evidence := strings.HasPrefix(rel, "tests/lab/evidence/")
	switch {
	case evidence && strings.HasSuffix(rel, ".go"):
		// Evidence is never code: a Go file there is no record, and the
		// tests/lab/*.go case below must not admit it.
		return false
	case rel == "internal/daemon/acct/hold.go", rel == "internal/daemon/acct/hold_lab.go",
		rel == "internal/daemon/acct/hold_test.go", rel == "internal/daemon/acct/hold_lab_test.go",
		rel == "tests/ci/lab_hold_test.go":
		return true
	case strings.HasPrefix(rel, "tests/lab/") && strings.HasSuffix(rel, ".go"):
		return true
	case strings.HasPrefix(rel, "docs/") && strings.HasSuffix(rel, ".md"):
		return true
	case evidence:
		// Committed lab evidence is a record of a run, never a build input:
		// L94 c4's summary names the tags its port49d was built with.
		return true
	}
	return false
}

// The allow-list is exactly the hold's own files, the lab harness, the
// docs, and the lab's committed evidence (a c4 summary records the tags its
// port49d was built with). Nothing else under tests/ may name the tag.
func TestTheHoldTagAllowListIsNarrow(t *testing.T) {
	for _, rel := range []string{
		"internal/daemon/acct/hold_lab.go", "tests/lab/l94_test.go", "docs/design/x.md",
		"tests/lab/evidence/L94-cisco_nxos/fixed/offered/c4-summary.txt",
	} {
		if !labHoldTagAllowed(rel) {
			t.Errorf("%s may name the tag", rel)
		}
	}
	for _, rel := range []string{
		"tests/x.go", "tests/ci/x_test.go", "tests/lab/evidence/x.go", "tests/lab/evidence/L94-x/c4.go", "tests/lab/x.txt", "tests/labx/evidence/x.txt", "internal/daemon/acct/acct.go",
		".goreleaser.yaml", "Dockerfile", "Makefile", "docs/x.yaml",
	} {
		if labHoldTagAllowed(rel) {
			t.Errorf("%s may not name the tag", rel)
		}
	}
}
