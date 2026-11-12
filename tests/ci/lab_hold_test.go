package ci

import (
	"go/build"
	"io/fs"
	"os"
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
	root := filepath.Join("..", "..")
	found := 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		name := d.Name()
		if d.IsDir() {
			if name == ".git" || name == "node_modules" || name == "site" && rel == "site" ||
				rel == "tests/lab/logs" || rel == "tests/lab/captures" || rel == "bin" || name == ".worktrees" {
				return filepath.SkipDir
			}
			return nil
		}
		// Never read a credential file.
		if name == "realm.json" || strings.HasSuffix(name, ".env") || strings.HasSuffix(name, "-key.pem") ||
			strings.HasSuffix(name, ".keytab") {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 4<<20 || !info.Mode().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		if strings.Contains(string(b), labAcctHoldTag) {
			found++
			if !allowed(rel) {
				t.Errorf("%s names the lab-only build tag %s: no build outside the lab may", rel, labAcctHoldTag)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if found < 3 {
		t.Fatalf("the tag was found in %d files: the scan is broken", found)
	}
}
